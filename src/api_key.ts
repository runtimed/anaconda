import {
  AuthType,
  ErrorType,
  RuntError,
  Scope,
  type ProviderContext,
  type AuthenticatedProviderContext,
  type Passport,
} from '@runtimed/extensions';
import {
  ApiKeyCapabilities,
  ApiKeyProvider,
  type CreateApiKeyRequest,
  type ApiKey,
  type ListApiKeysRequest,
} from '@runtimed/extensions/providers/api_key';
import * as jose from 'jose';

type ExtensionConfig = {
  apiKeyUrl: string;
  userinfoUrl: string;
};

type AnacondaWhoamiResponse = {
  passport: {
    user_id: string;
    profile: {
      email: string;
      first_name: string;
      last_name: string;
      is_confirmed: boolean;
    };
    scopes: string[];
    source: string;
  };
};
type AnacondaCreateApiKeyRequest = {
  scopes: string[];
  user_created: boolean;
  name: string;
  tags: string[];
  expires_at: string;
};

type AnacondaCreateApiKeyResponse = {
  id: string;
  api_key: string;
  expires_at: string;
};

type AnacondaGetApiKeyResponse = {
  id: string;
  name: string;
  user_created: boolean;
  tags: string[];
  scopes: string[];
  created_at: string;
  expires_at: string;
};

const getExtensionConfig = (context: ProviderContext): ExtensionConfig => {
  let config: ExtensionConfig;
  if (!context.env.EXTENSION_CONFIG) {
    throw new RuntError(ErrorType.ServerMisconfigured, {
      message: 'The EXTENSION_CONFIG environment variable is not properly set',
    });
  }
  try {
    config = JSON.parse(context.env.EXTENSION_CONFIG) as ExtensionConfig;
  } catch (error) {
    throw new RuntError(ErrorType.ServerMisconfigured, {
      message: 'The EXTENSION_CONFIG environment variable is not properly set',
      cause: error as Error,
    });
  }
  if (!config.apiKeyUrl || !config.userinfoUrl) {
    throw new RuntError(ErrorType.ServerMisconfigured, {
      message: 'The EXTENSION_CONFIG environment variable is missing required fields',
    });
  }
  return config;
};

function createFailureHandler(url: string) {
  return (err: unknown) => {
    throw new RuntError(ErrorType.Unknown, {
      message: `Failed to fetch from ${url}`,
      cause: err as Error,
    });
  };
}

async function handleAnacondaResponse<T>(response: Response): Promise<T> {
  let body: string;
  try {
    body = await response.text();
  } catch (error) {
    throw new RuntError(ErrorType.Unknown, {
      message: `Failed to get the body from ${response.url}`,
      cause: error as Error,
    });
  }
  if (response.status === 400) {
    throw new RuntError(ErrorType.InvalidRequest, {
      message: 'Invalid request',
      responsePayload: {
        upstreamCode: response.status,
      },
      debugPayload: {
        upstreamBody: body,
      },
    });
  }
  if (response.status === 401) {
    throw new RuntError(ErrorType.AuthTokenInvalid, {
      responsePayload: {
        upstreamCode: response.status,
      },
      debugPayload: {
        upstreamBody: body,
      },
    });
  }
  if (response.status === 403) {
    throw new RuntError(ErrorType.AccessDenied, {
      responsePayload: {
        upstreamCode: response.status,
      },
      debugPayload: {
        upstreamBody: body,
      },
    });
  }
  if (response.status === 404) {
    throw new RuntError(ErrorType.NotFound, {
      responsePayload: {
        upstreamCode: response.status,
      },
      debugPayload: {
        upstreamBody: body,
      },
    });
  }
  if (!response.ok) {
    throw new RuntError(ErrorType.Unknown, {
      responsePayload: {
        upstreamCode: response.status,
      },
      debugPayload: {
        upstreamBody: body,
      },
    });
  }
  if (response.status === 204) {
    return undefined as T;
  }
  try {
    return JSON.parse(body) as T;
  } catch (error) {
    throw new RuntError(ErrorType.Unknown, {
      message: 'Invalid JSON response',
      responsePayload: {
        upstreamCode: response.status,
      },
    });
  }
}

const anacondaToRuntScopes = (scopes: string[]): Scope[] => {
  let result: Scope[] = [];
  for (const scope of scopes) {
    if (scope === 'cloud:read') {
      result.push(Scope.RuntRead);
    }
    if (scope === 'cloud:write') {
      result.push(Scope.RuntExecute);
    }
  }
  return result;
};

const anacondaToRuntApiKey = (
  id: string,
  context: AuthenticatedProviderContext,
  anacondaResponse: AnacondaGetApiKeyResponse
): ApiKey => {
  return {
    id,
    userId: context.passport.user.id,
    name: anacondaResponse.name,
    scopes: anacondaToRuntScopes(anacondaResponse.scopes),
    expiresAt: anacondaResponse.expires_at,
    userGenerated: anacondaResponse.user_created,
    revoked: false,
  };
};

const provider: ApiKeyProvider = {
  capabilities: new Set([ApiKeyCapabilities.Delete]),
  isApiKey: (context: ProviderContext): boolean => {
    if (!context.bearerToken) {
      return false;
    }
    const unverified = jose.decodeJwt(context.bearerToken);
    return unverified.ver === 'api:1';
  },
  validateApiKey: async (context: ProviderContext): Promise<Passport> => {
    if (!context.bearerToken) {
      throw new RuntError(ErrorType.MissingAuthToken);
    }
    const config = getExtensionConfig(context);
    const whoami: AnacondaWhoamiResponse = await fetch(config.userinfoUrl, {
      headers: {
        Authorization: `Bearer ${context.bearerToken}`,
      },
    })
      .catch(createFailureHandler(config.userinfoUrl))
      .then(handleAnacondaResponse<AnacondaWhoamiResponse>);

    if (whoami.passport.source !== 'api_key') {
      throw new RuntError(ErrorType.AuthTokenInvalid, {
        message: 'Non api key used',
        debugPayload: {
          upstreamCode: 401,
          upstreamBody: whoami,
        },
      });
    }

    let scopes: Scope[] = anacondaToRuntScopes(whoami.passport.scopes);
    return {
      type: AuthType.ApiKey,
      user: {
        id: whoami.passport.user_id,
        email: whoami.passport.profile.email,
        givenName: whoami.passport.profile.first_name,
        familyName: whoami.passport.profile.last_name,
      },
      claims: jose.decodeJwt(context.bearerToken),
      scopes,
      resources: null,
    };
  },
  createApiKey: async (context: AuthenticatedProviderContext, request: CreateApiKeyRequest): Promise<string> => {
    const config = getExtensionConfig(context);
    const scopeMapping: Record<Scope, string> = {
      [Scope.RuntRead]: 'cloud:read',
      [Scope.RuntExecute]: 'cloud:write',
    };

    const requestBody: AnacondaCreateApiKeyRequest = {
      scopes: request.scopes.map(scope => scopeMapping[scope]),
      user_created: request.userGenerated,
      name: request.name ?? 'runt-api-key',
      tags: ['runt'],
      expires_at: request.expiresAt,
    };
    let result: AnacondaCreateApiKeyResponse = await fetch(config.apiKeyUrl, {
      method: 'POST',
      body: JSON.stringify(requestBody),
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${context.bearerToken}`,
      },
    })
      .catch(createFailureHandler(config.apiKeyUrl))
      .then(handleAnacondaResponse<AnacondaCreateApiKeyResponse>);
    return result.api_key;
  },
  getApiKey: async (context: AuthenticatedProviderContext, id: string): Promise<ApiKey> => {
    // Anaconda's API auth doesn't have an endpoint to get a single api key
    // Instead, we have to list all of them and then filter out the correct one
    const config = getExtensionConfig(context);
    const result: AnacondaGetApiKeyResponse[] = await fetch(config.apiKeyUrl, {
      headers: {
        Authorization: `Bearer ${context.bearerToken}`,
      },
    })
      .catch(createFailureHandler(config.apiKeyUrl))
      .then(handleAnacondaResponse<AnacondaGetApiKeyResponse[]>);
    const match = result.find(r => r.id === id);
    if (!match) {
      throw new RuntError(ErrorType.NotFound, {
        message: 'Api key not found',
      });
    }
    return anacondaToRuntApiKey(id, context, match);
  },
  listApiKeys: async (context: AuthenticatedProviderContext, request: ListApiKeysRequest): Promise<ApiKey[]> => {
    const config = getExtensionConfig(context);
    const result: AnacondaGetApiKeyResponse[] = await fetch(config.apiKeyUrl, {
      headers: {
        Authorization: `Bearer ${context.bearerToken}`,
      },
    })
      .catch(createFailureHandler(config.apiKeyUrl))
      .then(handleAnacondaResponse<AnacondaGetApiKeyResponse[]>);
    return result.map(r => anacondaToRuntApiKey(r.id, context, r));
  },
  revokeApiKey: async (_context: AuthenticatedProviderContext, _id: string): Promise<void> => {
    throw new RuntError(ErrorType.CapabilityNotAvailable, {
      message: 'revoke capability is not supported',
    });
  },
  deleteApiKey: async (context: AuthenticatedProviderContext, id: string): Promise<void> => {
    const config = getExtensionConfig(context);
    await fetch(`${config.apiKeyUrl}/${id}`, {
      method: 'DELETE',
      headers: {
        Authorization: `Bearer ${context.bearerToken}`,
      },
    })
      .catch(createFailureHandler(config.apiKeyUrl))
      .then(handleAnacondaResponse<void>);
  },
};

export default provider;

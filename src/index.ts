import { BackendExtension } from '@runtimed/extensions';
import apiKeyProvider from './api_key';

const extension: BackendExtension = {
  apiKey: apiKeyProvider,
};
export default extension;

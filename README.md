# @runtimed/anaconda

This extension provides the Anaconda-specific customizations to the Runt Web.
It is utilized on https://app.runt.run and integrates the api key API (with more integrations to come)

# Development

This is a simple typescript repository. You just `npm install` to set up dependencies. When you're ready to make a commit, run `npm run build` and `npm run format` to ensure the types pass & format the files respectively. If you forget, the CI will check it for you

# Publishing

1. Create a new branch
1. Update the [CHANGELOG.md](./CHANGELOG.md)
1. Change the version in package.json
1. run `npm install` to update the package-lock.json file
1. Commit, and create a PR
1. Merge the PR into main
1. Create a new release. Copy over the contents from the [CHANGELOG](./CHANGELOG.md)
1. The [publish](./.github/workflows/publish.yml) action will automatically push the release to npm

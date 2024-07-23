![badge-labs](https://user-images.githubusercontent.com/327285/230928932-7c75f8ed-e57b-41db-9fb7-a292a13a1e58.svg)

# Project Analysis

Project Analysis is a tool that scan the FINOS (Fintech Open Source Foundation) GitHub repositories and:
- Generates a readme of readme's, which can be used as a landing page for GitHub Organizations.
- Builds a project health report (in CSV format) that can be used to analyze the health of the projects.

## Features

- **Project Activity Analytics**: Gather and analyze data about project activity, including commit frequency, issue tracking, and pull request statistics.
- **README Summarization**: Automatically generate summaries for project README files to provide a quick overview of each project.
- **Visualization**: Generate visual representations of project activity and README summaries for better insights.

## Scanning the FINOS Project Landscape

**Clone the repository**:

```sh
git clone https://github.com/finos-labs/project-analysis.git
cd project-analysis
```

To scan the FINOS project landscape and gather data, run:

```sh
LANDSCAPE_SCANNING_TOKEN={your-github-personal-access-token} 
mvn spring-boot:run
```

To build the Jupyter notebook:

```sh
python3 -m venv env
./env/bin/python -m pip install -r requirements.txt
```

Open `project-report.ipynb` in VS Code and run the notebook; make sure that the `Jupyter` VS Code Extension is installed.

#### Generating a Pull Request

To create a [pull request to Project Analysis](https://github.com/finos-labs/project-analysis/pulls) at the end of the run, set this before running:

```sh
SPRING_PROFILES_ACTIVE=pr
```

#### Generating a Personal Access Token

To generate a personal access token, follow the instructions [here](https://docs.github.com/en/github/authenticating-to-github/creating-a-personal-access-token).

The PAT must have the following scopes enabled:
- Under `repo` the `public_repo` scope must be enabled.
- Under  `adimin:org` the `read:org` scope must be enabled.
- Under `project` the `project:read` scope must be enabled.

#### Project Reporting Structure

| Column name | description |
| ----------- | ----------- |
| Score | Issue Activity + Commit Activity |
| Pass | TO BE REMOVED |
| Organisation | Name of the GitHub organisation |
| Repo Name | Name of the GitHub repository |
| Project Name | Name of the FINOS project this repository belongs to, parsed from https://github.com/finos/finos-landscape/blob/master/landscape.yml |
| Project Type | Software Project or Special Interest Group, parsed from https://github.com/finos/finos-landscape/blob/master/landscape.yml |
| Project Stage | FINOS Lifecycle Stage, parsed from https://github.com/finos/finos-landscape/blob/master/landscape.yml |
| Stage | Finos Lifecycle Stage, parsed from README.md badges - https://community.finos.org/docs/governance/Software-Projects/project-lifecycle |
| Github Archived | Check if the GitHub repository is marked as archived, using GitHub API |
| License | Repo license, pulled from GitHub Api - https://community.finos.org/docs/governance/Software-Projects/license-categories |
| Meeting attendance | All comments to issues labeled as `meeting` in the last X days |
| Issue/PR Activity | All issue creations and comments in the last X days (except for those with label `meeting`) |
| Issue/PR lifespan | Average issue lifespan in the last X days |
| Commit Activity | Count number of commits in last 6 months, maxed at 100 (TODO - remove the 100 max) |
| OpenSSF Best Practices | The OpenSSF Best Practices score, parsed from README.md badges - https://www.bestpractices.dev/en |
| Branch Protection | Check branch rules: returns the number of approvers, 0 if no approvers are set, -1 if the is no branch protection enabled on the main branch |
| SemGrep | Checks existance of .github/workflows/semgrep.yml file - (TODO - would be better to check GitHub Actions execution) | 
| CVE Scanning | Checks existance of .github/workflows/cve-scanning.yml file - (TODO - would be better to check GitHub Actions execution) |
| Default Branch Name | Checks if default branch name is `main` |
| Admins | List of users that have admin rights on the repository (expected to be 0, since only finos-admin should have Admin rights on FINOS repositories) |
| Issue Participants | List of all participants for issues loaded in Issue Activity column |
| Committers | List of all repository committers |
| Readme Length | Number of characters of README.md |

#### Project Health
- 

Unmaintained
Low activity
Average activity
High activity


## Contributing

1. Fork it (<https://github.com/finos-labs/project-analysis/fork>)
2. Create your feature branch (`git checkout -b feature/fooBar`)
3. Read our [contribution guidelines](.github/CONTRIBUTING.md) and [Community Code of Conduct](https://www.finos.org/code-of-conduct)
4. Commit your changes (`git commit -am 'Add some fooBar'`)
5. Push to the branch (`git push origin feature/fooBar`)
6. Create a new Pull Request

## License

Copyright 2024 FINOS

Distributed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0).

SPDX-License-Identifier: [Apache-2.0](https://spdx.org/licenses/Apache-2.0)

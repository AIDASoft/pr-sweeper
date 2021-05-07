# GitHub Action: aidasoft/pr-sweeper
[![python](https://github.com/AIDASoft/pr-sweeper/actions/workflows/pylint.yml/badge.svg)](https://github.com/AIDASoft/pr-sweeper/actions/workflows/pylint.yml)

This GitHub Action cheery picks merged PRs to selected branches based on labels given to PRs.

## Instructions

### Prerequisites
This action depends on the user to call the action `uses: actions/checkout@v2` before using `uses: aidasoft/pr-sweeper@v1`. GitHub Actions currently do not support calling the action `checkout` from within `pr-sweeper`, this needs to be done explicitly by the user. Furthermore there are two aspects that need to considered when configuring the `checkout` action.

Firstly the number of commits to fetch. As the `pr-sweeper` needs a local checkout of the repository to find merge commits, it is necessary that you setup `fetch-depth` to an appropriate value that covers the sweeping time range. If in doubt you can always set `fetch-depth: 0` and the `checkout` action will checkout the whole history e.g.:
```yml
- uses: actions/checkout@v2
  with:
    fetch-depth: 0
```

Secondly the `pr-sweeper` action offers two strategies what to do with merge commits, either you cherry-pick them to a new branch or you merge them to a new branch. Cherry-picking is currently not possible via the GitHub REST API (for discussion see [this topic](https://github.community/t/do-a-cherry-pick-via-the-api/14573)) therefore it is performed in the local checkout, hence you need to add to the `checkout` action the GitHub Personal Access Token (PAT) via `token`, to enable pushing back to the repository e.g.:
```yml
- uses: actions/checkout@v2
  with:
    fetch-depth: 0
    token: ${{ secrets.PAT }}
```

### Example

You can use this GitHub Action in a workflow in your own repository with `uses: aidasoft/pr-sweeper@v1`.

A minimal job example for GitHub-hosted runners of type `ubuntu-latest`:
```yaml
jobs:
  sweep_PR:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
      with:
        fetch-depth: 0
        token: ${{ secrets.PAT }}
    - uses: aidasoft/pr-sweeper@v1
      with:
        github-pat: ${{ secrets.PAT }}
```
In this case the action will automatically resolve merge commits in the current branch in the last 24 hours and try to find the matching pull requests on GitHub. If the pull request has a label of the format `alsoTargeting:_target_branch_` the action will create a new branch in the repository based on `_target_branch_` and try to cheery-pick or merge the merge commit of the relevant PR to this newly created branch. If successful a PR with this newly created branch to `_target_branch_` will be created and it will receive the label `sweep:from _original_branch_` and the original PR will receive a label `sweep:done`. If at any step this operation something will fail, the original PR will receive in addition to `sweep:done` also `sweep:failed`. The label `sweep:done` only indicates that `pr-sweeper` has run once over this PR not that it was successful.

### Parameters
The following parameters are supported:
 - `branch`: remote branch whose merge commits should be swept (default: `auto` - branch the action if executed on)
 - `github-pat`: [GitHub Personal Access Token](https://github.com/settings/tokens)
 - `project-name`: GitHub project with namespace e.g. user/my-project (default: `auto` - inferred from the action environment)
 - `since`: start of time interval for sweeping PR (default: `1 day ago`)
 - `strategy`: option if you want to cheery-pick the merge commit or merge it (options: `merge` or `cherry-pick`)
 - `until`: end of time interval for sweeping PR (default: `now`)

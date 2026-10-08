# urma-git

**Publish Git snapshots and recover code beyond its original host.**

[crates.io](https://crates.io/crates/urma-git) · [API reference](https://docs.rs/urma-git/latest/urma_git/) · [Source](https://github.com/urma-protocol/urma/tree/master/urma-git) · [URMA](https://urma.rosint.org)

Use `urma-git` for snapshot preparation, content review, publication, proof recovery and verified checkout. It gives committed code another preservation and distribution route when a hosting account or repository is removed.

## Get started

```sh
cargo add urma-git
```

## API guide

| Entry point | Use it for |
| --- | --- |
| [`snapshot`](https://docs.rs/urma-git/latest/urma_git/snapshot/) | Freeze and inspect the committed HEAD snapshot. |
| [`inventory`](https://docs.rs/urma-git/latest/urma_git/inventory/) | Inventory the Git objects needed by the snapshot. |
| [`review`](https://docs.rs/urma-git/latest/urma_git/review/) | Content scanning and review records. |
| [`plans`](https://docs.rs/urma-git/latest/urma_git/plans/) | Bind a reviewed snapshot to a publication plan. |
| [`workflows`](https://docs.rs/urma-git/latest/urma_git/workflows/) | Prepare, publish, resume and recover snapshot workflows. |
| [`proofs`](https://docs.rs/urma-git/latest/urma_git/proofs/) | Retained transaction proofs and verification. |
| [`checkout`](https://docs.rs/urma-git/latest/urma_git/checkout/) | Materialize recovered content as a working repository. |

## Where it fits

For command-line use, install [urma-cli](https://crates.io/crates/urma-cli) and start with `urma git --help`. Library users can begin with `snapshot::prepare`, then compose the publication and recovery operations in `workflows`. The `git` executable must be available for Git operations.

## Boundaries

The snapshot is HEAD-only, not an archive of every branch and the entire repository history. Review what will become public before approving publication. Censorship resistance comes from additional accessible recovery paths; it does not guarantee that every network or copy will remain reachable.

## License

[0BSD](https://github.com/urma-protocol/urma/blob/master/LICENSE). Part of the [URMA workspace](https://github.com/urma-protocol/urma), maintained by Cristian Zmole. [Project contact](mailto:urma@rosint.org).

use super::headers::prove_batch;
use crate::config::P2P_MEDIAN_TIME_SPAN;
use crate::error::{Error, ensure};
use bitcoin::block::Header;
use urma_chain::observation::Chain;

/// Explicit, checkpoint-relative bootstrap with sufficient preceding history
/// for difficulty and median-time checks from the first successor onwards.
///
/// The operator trusts the anchor's chain membership and height. Its hash binds
/// the ancestor bytes; their individual PoW is also checked. This is not a
/// contextual consensus validation of history before the anchor, nor evidence
/// that the supplied chain has the greatest work on the public network.
/// Ancestors provide verification context, not an earlier selectable tip or
/// application scan coverage. No successor hash is trusted or bypassed.
#[derive(Clone, Debug)]
pub struct HeaderBootstrap {
    chain: Chain,
    height: u64,
    header: Header,
    ancestors: Vec<Header>,
}

impl HeaderBootstrap {
    /// `ancestors` contains exactly `min(height, context_headers(chain))`
    /// headers, oldest first, ending immediately before `header`.
    /// Validation completes before the value can be used to open any cache.
    pub fn new(
        chain: Chain,
        height: u64,
        header: Header,
        ancestors: Vec<Header>,
    ) -> Result<Self, Error> {
        let count = context_headers(chain);
        let expected = usize::try_from(height.min(u64::try_from(count)?))?;
        ensure!(
            ancestors.len() == expected,
            "bootstrap needs exactly {expected} ancestors"
        );
        let oldest = ancestors.first().unwrap_or(&header);
        if height == u64::try_from(ancestors.len())? {
            ensure!(
                oldest.block_hash() == chain.genesis()?.0,
                "bootstrap prefix does not start at the configured chain genesis"
            );
        }
        for (previous, next) in ancestors
            .iter()
            .zip(ancestors.iter().skip(1).chain(std::iter::once(&header)))
        {
            ensure!(
                next.prev_blockhash == previous.block_hash(),
                "bootstrap ancestors do not connect to the trusted anchor"
            );
        }
        prove_batch(chain, &ancestors)?;
        prove_batch(chain, std::slice::from_ref(&header))?;
        Ok(Self {
            chain,
            height,
            header,
            ancestors,
        })
    }

    pub fn chain(&self) -> Chain {
        self.chain
    }
    pub fn height(&self) -> u64 {
        self.height
    }
    pub fn header(&self) -> &Header {
        &self.header
    }
    pub fn ancestors(&self) -> &[Header] {
        &self.ancestors
    }

    pub(super) fn into_parts(self) -> (Chain, u64, Header, Vec<Header>) {
        (self.chain, self.height, self.header, self.ancestors)
    }
}

/// Ancestors before the anchor, excluding the anchor itself. The extra anchor
/// yields lookback+1 preceding headers and the full median-time window.
pub fn context_headers(chain: Chain) -> usize {
    // All supported chain parameters fit usize on supported platforms.
    // Use the interval as well so minimum-difficulty lookback cannot truncate
    // before the last period boundary if those parameters later diverge.
    chain
        .params()
        .retarget_lookback
        .max(chain.params().retarget_interval - 1)
        .max((P2P_MEDIAN_TIME_SPAN - 1) as u64) as usize
}

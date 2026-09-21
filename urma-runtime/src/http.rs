use crate::error::Error;

pub(crate) fn body(response: minreq::ResponseLazy, limit: usize) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    for byte in response.take(limit + 1) {
        bytes.push(byte?.0);
    }
    Ok(bytes)
}

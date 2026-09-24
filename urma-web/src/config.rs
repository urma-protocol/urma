use crate::{
    error::{WebError, ensure_web},
    package::Package,
};

pub const MIME_BY_EXTENSION: &[(&str, &str)] = &[
    ("html", "text/html"),
    ("htm", "text/html"),
    ("css", "text/css"),
    ("js", "text/javascript"),
    ("mjs", "text/javascript"),
    ("wasm", "application/wasm"),
    ("json", "application/json"),
    ("txt", "text/plain"),
    ("md", "text/plain"),
    ("xml", "application/xml"),
    ("svg", "image/svg+xml"),
    ("png", "image/png"),
    ("jpg", "image/jpeg"),
    ("jpeg", "image/jpeg"),
    ("gif", "image/gif"),
    ("webp", "image/webp"),
    ("ico", "image/x-icon"),
    ("avif", "image/avif"),
    ("woff2", "font/woff2"),
    ("woff", "font/woff"),
    ("ttf", "font/ttf"),
    ("otf", "font/otf"),
    ("mp3", "audio/mpeg"),
    ("ogg", "audio/ogg"),
    ("mp4", "video/mp4"),
    ("webm", "video/webm"),
    ("pdf", "application/pdf"),
    ("apk", "application/vnd.android.package-archive"),
    ("zip", "application/zip"),
    ("bin", "application/octet-stream"),
];

pub fn mime_for_extension(extension: &str) -> Result<&'static str, WebError> {
    for (known, mime) in MIME_BY_EXTENSION {
        if *known == extension {
            return Ok(mime);
        }
    }
    Err(WebError::Missing(format!(
        "no MIME for extension {extension:?}; pass --mime {extension}=type/subtype"
    )))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_path_bytes: usize,
    pub max_segments: usize,
    pub max_segment_bytes: usize,
    pub max_mime_bytes: usize,
    pub max_file_bytes: usize,
    pub max_package_bytes: usize,
}

impl Limits {
    pub const DEFAULT: Self = Self {
        max_path_bytes: 1024,
        max_segments: 32,
        max_segment_bytes: 255,
        max_mime_bytes: 128,
        max_file_bytes: 32 * 1024 * 1024,
        max_package_bytes: 64 * 1024 * 1024,
    };

    fn check_path(&self, path: &str) -> Result<(), WebError> {
        ensure_web!(
            path.len() <= self.max_path_bytes,
            "client policy: path longer than {} bytes: {path:?}",
            self.max_path_bytes
        );
        let mut segments = 0;
        for segment in path.split('/') {
            segments += 1;
            ensure_web!(
                segment.len() <= self.max_segment_bytes,
                "client policy: path segment longer than {} bytes: {path:?}",
                self.max_segment_bytes
            );
        }
        ensure_web!(
            segments <= self.max_segments,
            "client policy: more than {} path segments: {path:?}",
            self.max_segments
        );
        Ok(())
    }

    fn check_mime(&self, mime: &str) -> Result<(), WebError> {
        ensure_web!(
            mime.len() <= self.max_mime_bytes,
            "client policy: MIME longer than {} bytes: {mime:?}",
            self.max_mime_bytes
        );
        Ok(())
    }

    pub fn check(&self, package: &Package) -> Result<(), WebError> {
        let mut total = 0usize;
        for file in &package.files {
            self.check_path(&file.path)?;
            self.check_mime(&file.mime)?;
            ensure_web!(
                file.bytes.len() <= self.max_file_bytes,
                "client policy: file larger than {} bytes: {:?}",
                self.max_file_bytes,
                file.path
            );
            total = total
                .checked_add(file.bytes.len())
                .ok_or_else(|| WebError::Invalid("package size overflow".into()))?;
        }
        for pin in &package.pinned {
            self.check_path(&pin.path)?;
            self.check_mime(&pin.mime)?;
        }
        ensure_web!(
            total <= self.max_package_bytes,
            "client policy: package files exceed {} bytes",
            self.max_package_bytes
        );
        Ok(())
    }
}

#[derive(Clone)]
pub struct Challenge(Vec<u8>);

impl Challenge {
    pub fn new(size_bytes: usize) -> Self {
        let data = (0..size_bytes).map(|_| rand::random()).collect::<Vec<u8>>();
        Challenge(data)
    }
}

impl std::fmt::Display for Challenge {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", base64::encode(&self.0))
    }
}

impl std::fmt::Debug for Challenge {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", base64::encode(&self.0))
    }
}

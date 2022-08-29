const RC4_STATE_LEN: usize = 256;

pub struct Rc4State {
    i: usize,
    j: usize,
    state: [u8; RC4_STATE_LEN]
}

impl Rc4State {
    pub fn new() -> Self {
        Self {
            i: 0,
            j: 0,
            state: [0; RC4_STATE_LEN]
        }
    }

    fn schedule_key(&mut self, key: &[u8]) {
        for i in 0..RC4_STATE_LEN {
            self.state[i] = i as u8;
        }

        let mut j: usize = 0;
        for i in 0..RC4_STATE_LEN {
            j = (j + self.state[i] as usize + key[i % key.len()] as usize) % RC4_STATE_LEN;
            let tmp = self.state[i];
            self.state[i] = self.state[j];
            self.state[j] = tmp;
        }
    }

    pub fn operate(&mut self, input: &[u8], key: &[u8]) -> Vec<u8> {
        if self.state[0] == 0 && self.state[1] == 0 {
            self.schedule_key(key);
        }

        let mut i: usize = 0;
        let mut j: usize = 0;
        let mut output = Vec::with_capacity(input.len());

        for pt_byte in input {
            i = (i + 1) % RC4_STATE_LEN;
            j = (j + self.state[i] as usize) % RC4_STATE_LEN;
            let tmp = self.state[i];
            self.state[i] = self.state[j];
            self.state[j] = tmp;

            let state_index = ((self.state[i] as usize) + (self.state[j] as usize)) % RC4_STATE_LEN;
            let ct_byte = self.state[state_index] ^ *pt_byte;
            output.push(ct_byte);
        }

        self.i = i;
        self.j = j;
        output
    }
}
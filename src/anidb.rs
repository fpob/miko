use aes::{
    cipher::{
        generic_array::{typenum::U16, GenericArray},
        BlockDecrypt, BlockEncrypt, KeyInit,
    },
    Aes128Dec, Aes128Enc,
};
use anyhow::{anyhow, bail};
use block_padding::{Padding, Pkcs7};
use flate2::read::ZlibDecoder;
use itertools::Itertools;
use std::{
    borrow::Cow,
    cell::Cell,
    fmt,
    io::{self, Read},
    net::UdpSocket,
    thread::sleep,
    time::{Duration, Instant},
};

const ANIDB_API_ADDR: &str = "api.anidb.net:9000";
const CLIENT_NAME: &str = "miko";
const CLIENT_VERSION: &str = "1";

#[derive(thiserror::Error, Debug)]
pub(crate) enum Error {
    #[error("{0}")]
    Anyhow(#[from] anyhow::Error),
    #[error("Failed to connect to the AniDB API")]
    Socket(#[from] io::Error),
    #[error("{0}")]
    Server(Response),
    #[error("{0}")]
    Client(Response),
}

pub(crate) struct Client {
    socket: UdpSocket,
    packet_count: Cell<usize>,
    packet_last_send: Cell<Instant>,
    session_key: Option<String>,
    encrypt_key: Option<[u8; 16]>,
}

impl Client {
    pub fn new() -> Result<Self, Error> {
        Ok(Self {
            socket: UdpSocket::bind(("0.0.0.0", 9900))?,
            packet_count: 0.into(),
            packet_last_send: Instant::now().into(),
            session_key: None,
            encrypt_key: None,
        })
    }

    fn send(&self, data: &str) -> Result<(), Error> {
        let data = data.as_bytes();

        let buf = if let Some(encrypt_key) = self.encrypt_key {
            Cow::Owned(encrypt(data, &encrypt_key))
        } else {
            Cow::Borrowed(data)
        };

        self.packet_count.set(self.packet_count.get() + 1);
        if self.packet_count.get() > 5 {
            let delay =
                Duration::from_secs(2).saturating_sub(self.packet_last_send.get().elapsed());
            sleep(delay);
        }

        let result = self
            .socket
            .send_to(&buf, ANIDB_API_ADDR)
            .map_err(Error::Socket);

        self.packet_last_send.set(Instant::now());

        result.and(Ok(()))
    }

    fn recv(&self) -> Result<String, Error> {
        let mut buf = vec![0; 1400];

        let received_bytes = self.socket.recv(&mut buf)?;
        buf.truncate(received_bytes);

        if let Some(encrypt_key) = self.encrypt_key {
            buf = decrypt(&buf, &encrypt_key)?;
        }

        if buf.len() >= 2 && buf[0] == 0 && buf[1] == 0 {
            buf = decompress(&buf)?;
        }

        String::from_utf8(buf).map_err(|_| Error::Anyhow(anyhow!("Failed to decode response")))
    }

    pub fn command<'a, 'b>(&'a self, command: &'b str) -> RequestBuilder<'a, 'b> {
        RequestBuilder::new(self, command)
    }

    fn send_request<'a, 'b>(&'a self, mut request: Request<'b>) -> Result<Response, Error>
    where
        'a: 'b,
    {
        match request.command {
            "PING" | "ENCODING" | "ENCRYPT" | "AUTH" | "VERSION" => {}
            _ => {
                if let Some(s) = &self.session_key {
                    request.params.push(("s", s));
                }
            }
        }

        let response = {
            let raw_request: String = request.into();
            self.send(&raw_request)?;

            let raw_response = self.recv()?;
            Response::parse(raw_response.as_str())?
        };

        match response.code {
            600..700 => Err(Error::Server(response)),
            500..600 => Err(Error::Client(response)),
            _ => Ok(response),
        }
    }

    #[allow(dead_code)]
    pub fn ping(&self) -> bool {
        self.command("PING").send().is_ok_and(|rv| rv.code == 300)
    }

    #[allow(dead_code)]
    pub fn check_session(&self) -> Result<(), Error> {
        let rv = self.command("UPTIME").send()?;
        if rv.code == 208 {
            Ok(())
        } else {
            Err(Error::Client(rv))
        }
    }

    pub fn auth(&mut self, username: &str, password: &str) -> Result<Response, Error> {
        let rv = self
            .command("AUTH")
            .param("user", username)
            .param("pass", password)
            .param("protover", "3")
            .param("enc", "UTF-8")
            .param("comp", "1")
            .param("client", CLIENT_NAME)
            .param("clientver", CLIENT_VERSION)
            .send()?;

        if !(rv.code == 200 || rv.code == 201) {
            return Err(Error::Client(rv));
        }

        let (session_key, message) = {
            let spl: Vec<_> = rv.message.splitn(2, ' ').collect();
            if spl.len() != 2 {
                return Err(Error::Anyhow(anyhow!("Failed to obtain session key")));
            }
            (spl[0].to_owned(), spl[1].to_owned())
        };

        self.session_key = Some(session_key);

        Ok(Response { message, ..rv })
    }

    pub fn logout(&mut self) -> Result<Response, Error> {
        let rv = self.command("LOGOUT").send()?;
        if rv.code == 203 {
            self.session_key = None;
            self.encrypt_key = None;
        }
        Ok(rv)
    }

    pub fn encrypt(&mut self, username: &str, api_key: &str) -> Result<Response, Error> {
        let rv = self
            .command("ENCRYPT")
            .param("user", username)
            .param("type", "1")
            .send()?;

        if rv.code != 209 {
            return Err(Error::Client(rv));
        }

        let (salt, message) = {
            let spl: Vec<_> = rv.message.splitn(2, ' ').collect();
            if spl.len() != 2 {
                return Err(Error::Anyhow(anyhow!("Failed to obtain encrypt key")));
            }
            (spl[0].to_owned(), spl[1].to_owned())
        };

        let encrypt_key = *md5::compute(format!("{api_key}{salt}").as_bytes());
        self.encrypt_key = Some(encrypt_key);

        Ok(Response { message, ..rv })
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        if self.session_key.is_some() {
            self.logout().ok();
        }
    }
}

pub(crate) struct RequestBuilder<'client, 'request>
where
    'client: 'request,
{
    client: &'client Client,
    request: Request<'request>,
}

impl<'client, 'request> RequestBuilder<'client, 'request> {
    fn new(client: &'client Client, command: &'request str) -> Self {
        Self {
            client,
            request: Request {
                command,
                params: vec![],
            },
        }
    }

    pub fn param(mut self, key: &'request str, value: &'request str) -> Self {
        self.request.params.push((key, value));
        self
    }

    pub fn send(self) -> Result<Response, Error> {
        self.client.send_request(self.request)
    }
}

#[derive(Debug)]
pub(crate) struct Request<'a> {
    pub command: &'a str,
    pub params: Vec<(&'a str, &'a str)>,
}

impl From<Request<'_>> for String {
    fn from(request: Request) -> String {
        let command = request.command.to_uppercase();
        let params = request
            .params
            .iter()
            .map(|(k, v)| format!("{}={}", k, v.replace('&', "&amp;")))
            .join("&");
        format!("{command} {params}")
    }
}

#[derive(Debug)]
pub(crate) struct Response {
    pub code: u32,
    pub message: String,
    pub data: Vec<Vec<String>>,
}

impl Response {
    fn parse(data: &str) -> Result<Self, Error> {
        let mut lines = data.split('\n');

        let mut status_line = lines
            .nth(0)
            .ok_or(anyhow::anyhow!("missing status line in the response"))?
            .splitn(2, ' ');
        let code = status_line
            .nth(0)
            .ok_or(anyhow::anyhow!("missing code in the response"))?
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid reponse code"))?;
        let message = status_line
            .nth(0)
            .ok_or(anyhow::anyhow!("missing message in the response"))?
            .to_owned();

        let data: Vec<Vec<_>> = lines
            .map(|l| l.split('|').map(|i| i.replace("<br />", "\n")).collect())
            .collect();

        Ok(Self {
            code,
            message,
            data,
        })
    }
}

impl fmt::Display for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message.to_lowercase())
    }
}

fn encrypt(buf: &[u8], key: &[u8; 16]) -> Vec<u8> {
    let key = GenericArray::from_slice(key);
    let cipher = Aes128Enc::new(key);

    let mut blocks: Vec<_> = buf
        .chunks(16)
        .map(|chunk| {
            if chunk.len() == 16 {
                *GenericArray::from_slice(chunk)
            } else {
                let mut block: GenericArray<_, U16> = GenericArray::default();
                block[..chunk.len()].copy_from_slice(chunk);
                Pkcs7::pad(&mut block, chunk.len());
                block
            }
        })
        .collect();

    if buf.len() % 16 == 0 {
        let mut block: GenericArray<_, U16> = GenericArray::default();
        Pkcs7::pad(&mut block, 0);
        blocks.push(block);
    }

    cipher.encrypt_blocks(&mut blocks);

    blocks.into_iter().flatten().collect()
}

fn decrypt(buf: &[u8], key: &[u8; 16]) -> anyhow::Result<Vec<u8>> {
    if buf.len() % 16 != 0 {
        bail!("failed to decrypt");
    }

    let key = GenericArray::from_slice(key);
    let cipher = Aes128Dec::new(key);

    let mut blocks: Vec<_> = buf
        .chunks(16)
        .map(GenericArray::from_slice)
        .cloned()
        .collect();

    cipher.decrypt_blocks(&mut blocks);

    Ok(Pkcs7::unpad_blocks(&blocks)
        .map_err(|_| anyhow!("failed to decrypt"))?
        .to_vec())
}

fn decompress(buf: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut new_buf: Vec<u8> = vec![];
    ZlibDecoder::new(&buf[2..]).read_to_end(&mut new_buf)?;
    Ok(new_buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_formatting() {
        let r = Request {
            command: "EXAMPLE",
            params: vec![("foo", "bar")],
        };
        let rs: String = r.into();
        assert_eq!(rs, "EXAMPLE foo=bar");
    }

    #[test]
    fn response_parsing() {
        let r = Response::parse("210 MYLIST ENTRY ADDED\n1234");
        assert!(r.is_some());

        let r = r.unwrap();
        assert_eq!(r.code, 210);
        assert_eq!(r.message, "MYLIST ENTRY ADDED");
        assert_eq!(r.data.len(), 1);
        assert_eq!(r.data[0].len(), 1);
        assert_eq!(r.data[0][0], "1234");
    }

    #[test]
    fn encrypt_decrypt_short() {
        let key = md5::compute(b"foobar");
        let buf = b"foobar".to_vec();
        let enc = vec![
            112, 119, 170, 204, 153, 143, 147, 241, 239, 97, 27, 192, 67, 5, 91, 68,
        ];

        let encrypted_buf = encrypt(&buf, &key);
        assert_eq!(encrypted_buf, enc);

        let decrypted_buf = decrypt(&encrypted_buf, &key).unwrap();
        assert_eq!(decrypted_buf, buf);
    }

    #[test]
    fn encrypt_decrypt_block() {
        let key = md5::compute(b"foobar");
        let buf = b"0123456789abcdef".to_vec();
        let enc = vec![
            70, 51, 33, 11, 196, 30, 222, 88, 140, 186, 210, 153, 51, 162, 107, 179, 223, 3, 131,
            121, 70, 112, 101, 16, 154, 76, 2, 69, 125, 242, 102, 152,
        ];

        let encrypted_buf = encrypt(&buf, &key);
        assert_eq!(encrypted_buf, enc);

        let decrypted_buf = decrypt(&encrypted_buf, &key).unwrap();
        assert_eq!(decrypted_buf, buf);
    }

    #[test]
    fn decrypt_junk() {
        let key = md5::compute(b"foobar");
        let enc = vec![1, 2, 3, 4];

        let res = decrypt(&enc, &key);
        assert!(res.is_err());
    }

    #[test]
    fn encrypt_decrypt_long() {
        let key = md5::compute(b"foobar");
        let buf = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vivamus nulla nibh, \
            aliquet et ornare mattis, condimentum vel justo."
            .to_vec();
        let enc = vec![
            233, 5, 216, 115, 82, 231, 237, 90, 237, 19, 167, 185, 111, 176, 113, 103, 52, 212,
            138, 65, 174, 117, 28, 222, 104, 65, 238, 224, 234, 151, 206, 103, 80, 80, 76, 46, 58,
            35, 205, 120, 226, 189, 39, 58, 62, 199, 177, 70, 111, 224, 212, 167, 151, 218, 55,
            197, 53, 240, 185, 100, 69, 8, 180, 245, 233, 53, 54, 142, 107, 6, 37, 94, 134, 66,
            182, 44, 112, 120, 250, 250, 93, 82, 60, 24, 153, 52, 113, 215, 144, 61, 1, 153, 201,
            228, 38, 237, 231, 61, 162, 126, 140, 229, 148, 185, 58, 142, 84, 142, 238, 71, 77,
            121, 75, 170, 135, 128, 226, 209, 213, 16, 5, 79, 2, 156, 41, 178, 224, 192,
        ];

        let encrypted_buf = encrypt(&buf, &key);
        assert_eq!(encrypted_buf, enc);

        let decrypted_buf = decrypt(&encrypted_buf, &key).unwrap();
        assert_eq!(decrypted_buf, buf);
    }

    #[test]
    fn decompress_data() {
        let compressed = vec![
            0, 0, 120, 156, 243, 72, 205, 201, 201, 87, 112, 204, 203, 116, 113, 2, 0, 23, 12, 3,
            179,
        ];
        let text = "Hello AniDB";

        match decompress(&compressed) {
            Ok(v) => assert_eq!(v, text.as_bytes()),
            Err(e) => assert!(false, "failed to decompress; {e}"),
        }
    }
}

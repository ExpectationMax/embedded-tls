#![macro_use]
#![allow(incomplete_features)]
#![feature(generic_associated_types)]
#![feature(min_type_alias_impl_trait)]
#![feature(impl_trait_in_bindings)]
#![feature(type_alias_impl_trait)]
#![feature(concat_idents)]

use core::future::Future;
use drogue_device::{
    drivers::tls::{config::*, tls_connection::*, *},
    traits::tcp::TcpError,
};
use heapless::consts;
use rand::rngs::OsRng;
use rand_core::{CryptoRng, RngCore};
use std::error::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, Duration};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .format_timestamp_nanos()
        .init();

    //    let mut stream = TcpStream::connect("http.sandbox.drogue.cloud:443").await?;
    let mut stream = TcpStream::connect("127.0.0.1:12345").await?;
    let socket = Socket { stream };

    log::info!("Connected");
    let tlsConfig: Config<OsRng, Aes128GcmSha256> = Config::new(OsRng);
    let mut tls: TlsConnection<OsRng, Socket, Aes128GcmSha256, consts::U32768, consts::U32768> =
        TlsConnection::new(unsafe { core::mem::transmute(&tlsConfig) }, socket);
    let result = tls.handshake().await;
    match result {
        Ok(_) => {
            log::info!("TLS handshake complete!");
        }
        Err(e) => {
            log::error!("Error during TLS handshake: {:?}", e);
        }
    }

    sleep(Duration::from_millis(1000)).await;

    tls.write(b"ping").await.expect("error writing data");

    let mut rx_buf = [0; 16384];
    let sz = tls.read(&mut rx_buf).await.expect("error reading data");
    log::info!("Read {} bytes: {:?}", sz, &rx_buf[..sz]);

    Ok(())
}

pub struct Socket {
    stream: TcpStream,
}

impl AsyncWrite for Socket {
    #[rustfmt::skip]
    type WriteFuture<'m> where Self: 'm = impl Future<Output = Result<usize, TcpError>> + 'm;
    fn write<'m>(&'m mut self, buf: &'m [u8]) -> Self::WriteFuture<'m> {
        async move { Ok(self.stream.write(buf).await?) }
    }
}

impl AsyncRead for Socket {
    #[rustfmt::skip]
    type ReadFuture<'m> where Self: 'm = impl Future<Output = Result<usize, TcpError>> + 'm;
    fn read<'m>(&'m mut self, buf: &'m mut [u8]) -> Self::ReadFuture<'m> {
        async move { Ok(self.stream.read(buf).await?) }
    }
}

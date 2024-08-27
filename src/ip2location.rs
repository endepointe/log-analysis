pub mod ip2location;
use reqwest::blocking::Client;
use std::error::Error;

use crate::zeek::zeek_log_proto::ZeekProtocol;
use crate::zeek::zeek_log::Data;
use crate::types::helpers::print_type_of;


#[cfg(feature = "ip2location")]
pub fn request(data: &mut Data) -> Option<String>//Result<reqwest::Response, Box<dyn Error>>
{
    //let url = format!("https://api.ip2location.io/?key={}&ip={}&format=json","the key", "ip");
    let url = format!("https://jsonplaceholder.typicode.com/posts/{}",1);
    let client = Client::new();
	let b = client.get(url).send();
    if let Ok(res) = b
    {
        let res = res.text().unwrap();
        dbg!(&res,&data.get_city());
        //*data = res;
        //dbg!(&res.text());  // Ok(string)
        //return Ok(res.text()?);
        //match res
        //{
        //    Response(val) => println!("{}", res.text()),
        //    Err(err) => println!("not sure what this is: {err:?}")
        //}
    }
    //match b?
    //{
    //    Ok(res) => dbg!(&res),
    //        //match res.text() 
    //        //{
    //        //    Ok(text) => {return text)},//println!("received response: {text:?}"),
    //        //    Err(err) => {return err;}//eprintln!("error received: {err:?}")
    //        //}
    //    Err(err) => {return err;}//eprintln!("{err:?}")
    //}
    //Ok(String::from("nothing."))
    None
}


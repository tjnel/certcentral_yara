import "pe"

rule MAL_Compromised_Cert_Crazy_Evil_Traffer_Team_GlobalSign_50A57A36055177255C77BDC6 {
   meta:
      description         = "Detects Crazy Evil Traffer Team with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-12"
      version             = "1.0"

      hash                = "4e699d74a9ea31ffc96a50110ad6e9d714770b1eedb0323a61826f233161632d"
      malware             = "Crazy Evil Traffer Team"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "Shenzhen Zhongxingda Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "50:a5:7a:36:05:51:77:25:5c:77:bd:c6"
      cert_thumbprint     = "5537AF203DEC357CCD876B8005EB7B88CFF4BEBD"
      cert_valid_from     = "2024-12-12"
      cert_valid_to       = "2025-12-13"

      country             = "CN"
      state               = "Guangdong"
      locality            = "Shenzhen"
      email               = "???"
      rdn_serial_number   = "91440300MA5H14K805"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "50:a5:7a:36:05:51:77:25:5c:77:bd:c6"
      )
}

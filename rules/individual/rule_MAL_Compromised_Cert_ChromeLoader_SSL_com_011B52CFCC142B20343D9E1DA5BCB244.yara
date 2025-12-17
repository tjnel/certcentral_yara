import "pe"

rule MAL_Compromised_Cert_ChromeLoader_SSL_com_011B52CFCC142B20343D9E1DA5BCB244 {
   meta:
      description         = "Detects ChromeLoader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-04-17"
      version             = "1.0"

      hash                = "5d9ac50c89635198603cdd5276a12bad80959d8346944b9d06ef0c662f92fe6f"
      malware             = "ChromeLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SYZYX LTD"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "01:1b:52:cf:cc:14:2b:20:34:3d:9e:1d:a5:bc:b2:44"
      cert_thumbprint     = "F768B1D2798B0264F9711891CE7980268816C349"
      cert_valid_from     = "2023-04-17"
      cert_valid_to       = "2024-04-16"

      country             = "GB"
      state               = "???"
      locality            = "London"
      email               = "???"
      rdn_serial_number   = "14708389"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "01:1b:52:cf:cc:14:2b:20:34:3d:9e:1d:a5:bc:b2:44"
      )
}

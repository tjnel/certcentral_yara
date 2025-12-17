import "pe"

rule MAL_Compromised_Cert_ChromeLoader_SSL_com_66A963E7EEFCA707FAA4F6C068E33F67 {
   meta:
      description         = "Detects ChromeLoader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-02-10"
      version             = "1.0"

      hash                = "2df3f0c50942cebf7d508364ade31de19a84a6d9377a7799b626abdf8f09a9bb"
      malware             = "ChromeLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "TELIX LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "66:a9:63:e7:ee:fc:a7:07:fa:a4:f6:c0:68:e3:3f:67"
      cert_thumbprint     = "F7EAD36C07F11FE932E6BACA357F2610C550CEE3"
      cert_valid_from     = "2023-02-10"
      cert_valid_to       = "2024-02-10"

      country             = "GB"
      state               = "???"
      locality            = "London"
      email               = "???"
      rdn_serial_number   = "14631498"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "66:a9:63:e7:ee:fc:a7:07:fa:a4:f6:c0:68:e3:3f:67"
      )
}

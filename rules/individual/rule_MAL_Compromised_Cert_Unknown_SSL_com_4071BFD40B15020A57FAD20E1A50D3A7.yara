import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_4071BFD40B15020A57FAD20E1A50D3A7 {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-09-14"
      version             = "1.0"

      hash                = "749d4056d5b6a0077f419e6e8c16c4655e370a5d1886695b7b65ddf547db137e"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Raecomm Services Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "40:71:bf:d4:0b:15:02:0a:57:fa:d2:0e:1a:50:d3:a7"
      cert_thumbprint     = "C650164579439A7BC20B4A73F70335D67663DCEA"
      cert_valid_from     = "2023-09-14"
      cert_valid_to       = "2024-09-13"

      country             = "GB"
      state               = "England"
      locality            = "Rowlands Gill"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "40:71:bf:d4:0b:15:02:0a:57:fa:d2:0e:1a:50:d3:a7"
      )
}

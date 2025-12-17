import "pe"

rule MAL_Compromised_Cert_Rhadamanthys_SSL_com_6811D075FB2BF13F59C9A797B0D3EBF9 {
   meta:
      description         = "Detects Rhadamanthys with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-01-25"
      version             = "1.0"

      hash                = "77ce108cd1d6751faaf043706a37af1c59fd1d087efeb1cfe5d22ae395566b5b"
      malware             = "Rhadamanthys"
      malware_type        = "Infostealer"
      malware_notes       = "An module infostealer malware: https://research.checkpoint.com/2025/rhadamanthys-0-9-x-walk-through-the-updates/"

      signer              = "LED LIGHT SP Z O O"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "68:11:d0:75:fb:2b:f1:3f:59:c9:a7:97:b0:d3:eb:f9"
      cert_thumbprint     = "2C547FCCE1000372134A0B6FE475861C8DA1AC7B"
      cert_valid_from     = "2024-01-25"
      cert_valid_to       = "2025-01-24"

      country             = "PL"
      state               = "Masovian Voivodeship"
      locality            = "Warszawa"
      email               = "???"
      rdn_serial_number   = "0000567855"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "68:11:d0:75:fb:2b:f1:3f:59:c9:a7:97:b0:d3:eb:f9"
      )
}

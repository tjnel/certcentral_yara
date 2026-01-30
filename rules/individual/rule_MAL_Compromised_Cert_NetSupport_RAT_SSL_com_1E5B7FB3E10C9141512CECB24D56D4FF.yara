import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_SSL_com_1E5B7FB3E10C9141512CECB24D56D4FF {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-22"
      version             = "1.0"

      hash                = "e5315d0b7e068b6e3130725a074e67bc3c9ae0f778562816475c8e54c256ca0c"
      malware             = "NetSupport RAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Flagship Promotion s. r. o."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "1e:5b:7f:b3:e1:0c:91:41:51:2c:ec:b2:4d:56:d4:ff"
      cert_thumbprint     = "B64366A3BE9FF011D5AEE1FC56CAC3FFF4D87827"
      cert_valid_from     = "2026-01-22"
      cert_valid_to       = "2027-01-22"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "1e:5b:7f:b3:e1:0c:91:41:51:2c:ec:b2:4d:56:d4:ff"
      )
}

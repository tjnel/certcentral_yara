import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_2CA80AA74A5EC29E23713A23D5C29A68 {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-11-04"
      version             = "1.0"

      hash                = "4779db5eb5116033e0f2e5d7fda041a4887830c778319d55b0bbbef55a6a0e7f"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "WORK PRODUCT, INC."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "2c:a8:0a:a7:4a:5e:c2:9e:23:71:3a:23:d5:c2:9a:68"
      cert_thumbprint     = "7612888362AD683E5366E63846A3A219C1DA250D"
      cert_valid_from     = "2024-11-04"
      cert_valid_to       = "2025-10-31"

      country             = "US"
      state               = "Colorado"
      locality            = "Golden"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "2c:a8:0a:a7:4a:5e:c2:9e:23:71:3a:23:d5:c2:9a:68"
      )
}

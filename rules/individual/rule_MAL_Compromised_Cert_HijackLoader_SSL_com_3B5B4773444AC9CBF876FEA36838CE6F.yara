import "pe"

rule MAL_Compromised_Cert_HijackLoader_SSL_com_3B5B4773444AC9CBF876FEA36838CE6F {
   meta:
      description         = "Detects HijackLoader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-23"
      version             = "1.0"

      hash                = "a153dd1ca451bdb9c83ed29aba2582195b42dae721aac78515eea97b7e4fe267"
      malware             = "HijackLoader"
      malware_type        = "Loader"
      malware_notes       = ""

      signer              = "A.I.D. Advanced Internet Design Oy"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "3b:5b:47:73:44:4a:c9:cb:f8:76:fe:a3:68:38:ce:6f"
      cert_thumbprint     = "50124B91181735FBC49E728CA9AD127EE32A17BD"
      cert_valid_from     = "2025-07-23"
      cert_valid_to       = "2026-07-23"

      country             = "FI"
      state               = "Uusimaa"
      locality            = "Kerava"
      email               = "???"
      rdn_serial_number   = "1504972-0"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "3b:5b:47:73:44:4a:c9:cb:f8:76:fe:a3:68:38:ce:6f"
      )
}

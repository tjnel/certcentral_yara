import "pe"

rule MAL_Compromised_Cert_BitRAT_DigiCert_0CED87BD70B092CB93B182FAC32655F6 {
   meta:
      description         = "Detects BitRAT with compromised cert (DigiCert)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-03-04"
      version             = "1.0"

      hash                = "083d5efb4da09432a206cb7fba5cef2c82dd6cc080015fe69c2b36e71bca6c89"
      malware             = "BitRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Creator Soft Limited"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert EV Code Signing CA (SHA2)"
      cert_serial         = "0c:ed:87:bd:70:b0:92:cb:93:b1:82:fa:c3:26:55:f6"
      cert_thumbprint     = "97B7602ED71480756CF6E4658A107F8278A48096"
      cert_valid_from     = "2021-03-04"
      cert_valid_to       = "2022-03-08"

      country             = "IE"
      state               = "???"
      locality            = "Dublin"
      email               = "???"
      rdn_serial_number   = "685089"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert EV Code Signing CA (SHA2)" and
         sig.serial == "0c:ed:87:bd:70:b0:92:cb:93:b1:82:fa:c3:26:55:f6"
      )
}

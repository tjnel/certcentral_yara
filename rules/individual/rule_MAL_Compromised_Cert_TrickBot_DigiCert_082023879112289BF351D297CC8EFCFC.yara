import "pe"

rule MAL_Compromised_Cert_TrickBot_DigiCert_082023879112289BF351D297CC8EFCFC {
   meta:
      description         = "Detects TrickBot with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2019-11-11"
      version             = "1.0"

      hash                = "1689b812aa652c7ac24aa9e71ef5bba8b2dde899b64da8b7df083d5c5c830746"
      malware             = "TrickBot"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "STA-R TOV"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert EV Code Signing CA (SHA2)"
      cert_serial         = "08:20:23:87:91:12:28:9b:f3:51:d2:97:cc:8e:fc:fc"
      cert_thumbprint     = "C6EEA9DFCF7146D075A724588DCF4A00A9C50565"
      cert_valid_from     = "2019-11-11"
      cert_valid_to       = "2020-11-18"

      country             = "UA"
      state               = "Dnipropetrovsk Oblast"
      locality            = "Kryvyi Rih"
      email               = "???"
      rdn_serial_number   = "39768949"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert EV Code Signing CA (SHA2)" and
         sig.serial == "08:20:23:87:91:12:28:9b:f3:51:d2:97:cc:8e:fc:fc"
      )
}

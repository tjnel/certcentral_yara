import "pe"

rule MAL_Compromised_Cert_OysterLoader_SSL_com_13CEA619DDE4C2A434A8974E4AC18FB4 {
   meta:
      description         = "Detects OysterLoader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-04"
      version             = "1.0"

      hash                = "7c88fc26ab4abd3798d8e0c1de7d2bb8f05d73ea2a209b443f01681b3cfc624c"
      malware             = "OysterLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "EOR SOFTWARE LTD"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "13:ce:a6:19:dd:e4:c2:a4:34:a8:97:4e:4a:c1:8f:b4"
      cert_thumbprint     = "0D1E89918C49DFE5214DFC822AB676D2253849D4"
      cert_valid_from     = "2025-09-04"
      cert_valid_to       = "2026-09-04"

      country             = "GB"
      state               = "???"
      locality            = "Ipswich"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "13:ce:a6:19:dd:e4:c2:a4:34:a8:97:4e:4a:c1:8f:b4"
      )
}

import "pe"

rule MAL_Compromised_Cert_Baoloader_GlobalSign_5499B3DF6966C9151EF0135D {
   meta:
      description         = "Detects Baoloader with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-01-17"
      version             = "1.0"

      hash                = "9c5d756045fd479a742b81241ccf439d02fc668581a3002913811a341278de43"
      malware             = "Baoloader"
      malware_type        = "Backdoor"
      malware_notes       = "This malware was originally used for adfraud but is a risk due to an arbitrary backdoor. For more information see https://expel.com/blog/the-history-of-appsuite-the-certs-of-the-baoloader-developer/ and https://www.gdatasoftware.com/blog/2025/08/38257-appsuite-pdf-editor-backdoor-analysis"

      signer              = "Eclipse Media Inc."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "54:99:b3:df:69:66:c9:15:1e:f0:13:5d"
      cert_thumbprint     = "42149963068EA92A3CECA7834B2979DEE9039BB9"
      cert_valid_from     = "2024-01-17"
      cert_valid_to       = "2027-01-17"

      country             = "PA"
      state               = "Panama"
      locality            = "Panama City"
      email               = "???"
      rdn_serial_number   = "155704432-2-2021"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "54:99:b3:df:69:66:c9:15:1e:f0:13:5d"
      )
}

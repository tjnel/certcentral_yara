import "pe"

rule MAL_Compromised_Cert_BaoLoader_GlobalSign_64351C662E8F81778E29BC8D {
   meta:
      description         = "Detects BaoLoader with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-03-24"
      version             = "1.0"

      hash                = "4c2678aed5975d0968569000dd0092de29584b626eaaaaa9873bf0295388d1f2"
      malware             = "BaoLoader"
      malware_type        = "Backdoor"
      malware_notes       = "This malware was originally used for adfraud but is a risk due to an arbitrary backdoor. For more information see https://expel.com/blog/the-history-of-appsuite-the-certs-of-the-baoloader-developer/ and https://www.gdatasoftware.com/blog/2025/08/38257-appsuite-pdf-editor-backdoor-analysis"

      signer              = "Drake Media Inc"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "64:35:1c:66:2e:8f:81:77:8e:29:bc:8d"
      cert_thumbprint     = "61E0D3D92882C136A6EADE1B90898BCDD4D05A5B"
      cert_valid_from     = "2023-03-24"
      cert_valid_to       = "2025-03-24"

      country             = "PA"
      state               = "Panamá"
      locality            = "Ciudad de Panamá"
      email               = "???"
      rdn_serial_number   = "155704428"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "64:35:1c:66:2e:8f:81:77:8e:29:bc:8d"
      )
}

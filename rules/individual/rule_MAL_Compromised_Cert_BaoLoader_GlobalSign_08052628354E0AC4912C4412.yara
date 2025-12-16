import "pe"

rule MAL_Compromised_Cert_BaoLoader_GlobalSign_08052628354E0AC4912C4412 {
   meta:
      description         = "Detects BaoLoader with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-11-02"
      version             = "1.0"

      hash                = "9104b6e9f63232535b1f2ccb516122cf07bb62d3175044d7699e49c79cbc8f60"
      malware             = "BaoLoader"
      malware_type        = "Backdoor"
      malware_notes       = "This malware was originally used for adfraud but is a risk due to an arbitrary backdoor. For more information see https://expel.com/blog/the-history-of-appsuite-the-certs-of-the-baoloader-developer/ and https://www.gdatasoftware.com/blog/2025/08/38257-appsuite-pdf-editor-backdoor-analysis"

      signer              = "Interlink Media Inc."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "08:05:26:28:35:4e:0a:c4:91:2c:44:12"
      cert_thumbprint     = "1B696B16E85A11F56D98D69721FDBE7B7688A9B6"
      cert_valid_from     = "2023-11-02"
      cert_valid_to       = "2026-11-02"

      country             = "PA"
      state               = "Panamá"
      locality            = "Ciudad de Panamá"
      email               = "innfang@interlinkmediainc.com"
      rdn_serial_number   = "155704402"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "08:05:26:28:35:4e:0a:c4:91:2c:44:12"
      )
}

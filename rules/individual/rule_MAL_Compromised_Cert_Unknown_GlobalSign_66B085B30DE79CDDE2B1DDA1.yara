import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_66B085B30DE79CDDE2B1DDA1 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-09-26"
      version             = "1.0"

      hash                = "7c82e966c458ed5be7ff7a727e73720968cd6d26eed382aa1f62cce6933399d0"
      malware             = "Unknown"
      malware_type        = "Backdoor"
      malware_notes       = "The MSI file contains a EXE for DLL sideloading. The DLL is a Nim malware implant."

      signer              = "ChasingFire Dream Technologies Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "66:b0:85:b3:0d:e7:9c:dd:e2:b1:dd:a1"
      cert_thumbprint     = "0C66883B1909D6188FFA8E4D59448B5A8D930294"
      cert_valid_from     = "2024-09-26"
      cert_valid_to       = "2025-09-27"

      country             = "CN"
      state               = "Hubei"
      locality            = "Wuhan"
      email               = "???"
      rdn_serial_number   = "91420115MA4L020L06"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "66:b0:85:b3:0d:e7:9c:dd:e2:b1:dd:a1"
      )
}

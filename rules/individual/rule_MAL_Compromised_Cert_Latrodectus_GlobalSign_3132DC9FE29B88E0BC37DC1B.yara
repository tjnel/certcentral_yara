import "pe"

rule MAL_Compromised_Cert_Latrodectus_GlobalSign_3132DC9FE29B88E0BC37DC1B {
   meta:
      description         = "Detects Latrodectus with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-31"
      version             = "1.0"

      hash                = "5f84809a778841f1dc64bc43d6bb1a822d6aa04a3ae65c5f9ad31a7fcb2cbca9"
      malware             = "Latrodectus"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Wuhan Yichuang Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "31:32:dc:9f:e2:9b:88:e0:bc:37:dc:1b"
      cert_thumbprint     = "D238EE4E135C39D2996CBB81FAD409BEE9A1F582"
      cert_valid_from     = "2025-03-31"
      cert_valid_to       = "2026-04-01"

      country             = "CN"
      state               = "Hubei"
      locality            = "Wuhan"
      email               = "???"
      rdn_serial_number   = "91420100MA49NX8T6M"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "31:32:dc:9f:e2:9b:88:e0:bc:37:dc:1b"
      )
}

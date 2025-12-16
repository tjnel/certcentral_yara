import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_493C157B7D0D910E46E98F84 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-01"
      version             = "1.0"

      hash                = "9f19ef9764dd9abc67b439321fee86baaf9f41b53cfc071f906d88c1b32312bb"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Anhui Wansanshi Internet of Things Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "49:3c:15:7b:7d:0d:91:0e:46:e9:8f:84"
      cert_thumbprint     = "D15CF39DA662C071CA63CD1DA7E8E94E59513903"
      cert_valid_from     = "2025-04-01"
      cert_valid_to       = "2026-04-02"

      country             = "CN"
      state               = "Anhui"
      locality            = "Wuhu"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "49:3c:15:7b:7d:0d:91:0e:46:e9:8f:84"
      )
}

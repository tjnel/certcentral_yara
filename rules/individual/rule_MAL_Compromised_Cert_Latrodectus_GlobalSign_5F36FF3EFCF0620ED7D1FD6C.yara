import "pe"

rule MAL_Compromised_Cert_Latrodectus_GlobalSign_5F36FF3EFCF0620ED7D1FD6C {
   meta:
      description         = "Detects Latrodectus with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-21"
      version             = "1.0"

      hash                = "69af1d10dd1dacae362ab8fd4e5bcc97ddb363cdeb06a4bf1bc3db4dfc68b1e1"
      malware             = "Latrodectus"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Wuxi Weitai Nano Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "5f:36:ff:3e:fc:f0:62:0e:d7:d1:fd:6c"
      cert_thumbprint     = "DAD62095A80EEA1E6DECF91F957E59BA562B27A1"
      cert_valid_from     = "2025-04-21"
      cert_valid_to       = "2026-04-22"

      country             = "CN"
      state               = "Jiangsu"
      locality            = "Wuxi"
      email               = "???"
      rdn_serial_number   = "91320214MA1YY96J3H"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "5f:36:ff:3e:fc:f0:62:0e:d7:d1:fd:6c"
      )
}

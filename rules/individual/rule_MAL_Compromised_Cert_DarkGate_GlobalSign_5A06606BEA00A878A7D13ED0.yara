import "pe"

rule MAL_Compromised_Cert_DarkGate_GlobalSign_5A06606BEA00A878A7D13ED0 {
   meta:
      description         = "Detects DarkGate with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-02-01"
      version             = "1.0"

      hash                = "9a3990e375cc3a3a9d6c659b5b5551900dcdc1e7fc8f807f85a951517c8ae96f"
      malware             = "DarkGate"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware was known to be multifunctional and evasive. Its main popularity was in 2024 during a period where there were open sales. See this for more information on its functionality: https://www.proofpoint.com/us/blog/email-and-cloud-threats/darkgate-malware"

      signer              = "OptiInnoMind Security Information Tech Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "5a:06:60:6b:ea:00:a8:78:a7:d1:3e:d0"
      cert_thumbprint     = "76F702077DDE4E7C079884CEE32E5628C639509E"
      cert_valid_from     = "2024-02-01"
      cert_valid_to       = "2025-01-31"

      country             = "CN"
      state               = "Guangdong"
      locality            = "Foshan"
      email               = "???"
      rdn_serial_number   = "91440605MACT3UA74D"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "5a:06:60:6b:ea:00:a8:78:a7:d1:3e:d0"
      )
}

import "pe"

rule MAL_Compromised_Cert_DarkGate_GlobalSign_34F3E42F122C45100811225D {
   meta:
      description         = "Detects DarkGate with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-11-15"
      version             = "1.0"

      hash                = "9e4f036dd6fbb45ce414cb5d040b3255b5ccc9ecacbfaf022b631545f9a19a02"
      malware             = "DarkGate"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware was known to be multifunctional and evasive. Its main popularity was in 2024 during a period where there were open sales. See this for more information on its functionality: https://www.proofpoint.com/us/blog/email-and-cloud-threats/darkgate-malware"

      signer              = "XUAN THANH CEMENT JOINT STOCK COMPANY"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "34:f3:e4:2f:12:2c:45:10:08:11:22:5d"
      cert_thumbprint     = "D2BA1F548EB15270386A9D203FCA3A0379A09913"
      cert_valid_from     = "2024-11-15"
      cert_valid_to       = "2025-11-16"

      country             = "VN"
      state               = "Ha Nam"
      locality            = "Ha Nam"
      email               = "phandinhtrinh1981@gmail.com"
      rdn_serial_number   = "0700576529"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "34:f3:e4:2f:12:2c:45:10:08:11:22:5d"
      )
}

import "pe"

rule MAL_Compromised_Cert_DarkGate_Certum_108060722A4579EEBE4C2A48FCA17948 {
   meta:
      description         = "Detects DarkGate with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-06-19"
      version             = "1.0"

      hash                = "108469e0649650f5d669251708a4380cb89bae61abd5a6b6c08c2168c2c5d40d"
      malware             = "DarkGate"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware was known to be multifunctional and evasive. Its main popularity was in 2024 during a period where there were open sales. See this for more information on its functionality: https://www.proofpoint.com/us/blog/email-and-cloud-threats/darkgate-malware"

      signer              = "Vieworks Limited"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "10:80:60:72:2a:45:79:ee:be:4c:2a:48:fc:a1:79:48"
      cert_thumbprint     = "BA45CF1EAAC16E6A01B95FA7D4AC3F08D1013950"
      cert_valid_from     = "2024-06-19"
      cert_valid_to       = "2025-06-19"

      country             = "GB"
      state               = "???"
      locality            = "London"
      email               = "???"
      rdn_serial_number   = "11833644"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "10:80:60:72:2a:45:79:ee:be:4c:2a:48:fc:a1:79:48"
      )
}

import "pe"

rule MAL_Compromised_Cert_Oyster_Microsoft_330003808CC20DE933506ACB4F00000003808C {
   meta:
      description         = "Detects Oyster with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-01"
      version             = "1.0"

      hash                = "eaebd963b1e8dc5d3bd53a4842401559700f3201cd6589870281ab5b1ab57af3"
      malware             = "Oyster"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "Alternative Power Systems Solutions LLC"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:03:80:8c:c2:0d:e9:33:50:6a:cb:4f:00:00:00:03:80:8c"
      cert_thumbprint     = "5E48471106CD3B222863E6A27B8C86F98DCE369A"
      cert_valid_from     = "2025-07-01"
      cert_valid_to       = "2025-07-04"

      country             = "US"
      state               = "Arizona"
      locality            = "Chandler"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:03:80:8c:c2:0d:e9:33:50:6a:cb:4f:00:00:00:03:80:8c"
      )
}

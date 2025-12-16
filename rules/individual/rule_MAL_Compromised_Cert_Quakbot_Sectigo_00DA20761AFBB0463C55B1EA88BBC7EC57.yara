import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_00DA20761AFBB0463C55B1EA88BBC7EC57 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2022-01-18"
      version             = "1.0"

      hash                = "a9db99b934cb21df04e03d2b0d08ea6e6aaaa31ed185cdcff3d0148ea28454a3"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "CLEVER CLOSE s.r.o."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "00:da:20:76:1a:fb:b0:46:3c:55:b1:ea:88:bb:c7:ec:57"
      cert_thumbprint     = "62590D0A1333574142A7CB65A9BC4D4874BD8563"
      cert_valid_from     = "2022-01-18"
      cert_valid_to       = "2023-01-18"

      country             = "CZ"
      state               = "Praha, Hlavní město"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "00:da:20:76:1a:fb:b0:46:3c:55:b1:ea:88:bb:c7:ec:57"
      )
}

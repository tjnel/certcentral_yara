import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_00D338F8A490E37E6C2BE80A0E349929FA {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-12-10"
      version             = "1.0"

      hash                = "dbc1c772413a6d461d8c5db0d1b2538d9879c3f6890c8be34fe9723b5817909f"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "SAGUARO ApS"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:d3:38:f8:a4:90:e3:7e:6c:2b:e8:0a:0e:34:99:29:fa"
      cert_thumbprint     = "9F039085397000D32A63A5AC092903E3655F9243"
      cert_valid_from     = "2020-12-10"
      cert_valid_to       = "2021-12-10"

      country             = "DK"
      state               = "???"
      locality            = "Vallensbæk Strand"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:d3:38:f8:a4:90:e3:7e:6c:2b:e8:0a:0e:34:99:29:fa"
      )
}

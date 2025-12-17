import "pe"

rule MAL_Compromised_Cert_RMMLoader_Sectigo_00F9248EA686FE42C08F22EE5A522CA067 {
   meta:
      description         = "Detects RMMLoader with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-24"
      version             = "1.0"

      hash                = "f6a85889f1e9d725f5807d9dab542d7367619bd91286678340a5e638f2b362a7"
      malware             = "RMMLoader"
      malware_type        = "Remote access tool"
      malware_notes       = "Loads NinjaOne RMM tool: https://app.any.run/tasks/0ef046ff-3ec7-4b18-8755-f7387e061a3f"

      signer              = "CÔNG TY TNHH XB FLOW TECHNOLOGIES"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:f9:24:8e:a6:86:fe:42:c0:8f:22:ee:5a:52:2c:a0:67"
      cert_thumbprint     = "D287FEC7DDC1CB3B4F34DE24C3A08033020CC4B8"
      cert_valid_from     = "2025-09-24"
      cert_valid_to       = "2026-10-24"

      country             = "VN"
      state               = "Quảng Trị"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "3101145367"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:f9:24:8e:a6:86:fe:42:c0:8f:22:ee:5a:52:2c:a0:67"
      )
}

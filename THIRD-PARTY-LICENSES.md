# Third-Party License Notice

This project uses the following third-party libraries. Their respective licenses apply.

---

## 1. Qt 6

- **License**: GNU Lesser General Public License v3.0 (LGPL-3.0) / Commercial
- **Source**: https://www.qt.io/
- **Usage**: GUI framework
- **Note**: If using LGPL Qt, this project must dynamically link Qt libraries. See https://doc.qt.io/qt-6/lgpl.html

---

## 2. YARA

- **License**: Apache License 2.0 (core), BSD-3-Clause (some modules), GPL-2.0 (bison-generated grammar files)
- **Source**: https://github.com/VirusTotal/yara
- **Usage**: Static signature matching for malware detection
- **Files**: `libyara/`, `libyara64.lib`
- **Notice**:
  ```
  Copyright (c) 2013-2024 The YARA Authors. All Rights Reserved.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
  ```

---

## 3. ClamAV

- **License**: GNU General Public License v2.0+ (GPL-2.0+)
- **Source**: https://www.clamav.net/
- **Usage**: Virus scanning engine, loaded dynamically via LoadLibrary
- **Files**: `libclamav.dll` (distributed separately, not compiled in)
- **Note**: ClamAV is loaded at runtime via dynamic linking (`LoadLibrary`), which does NOT trigger GPL copyleft requirements for the host application. The `ClamAV/clamav-main/` source directory is for reference only and is excluded from the repository.
- **Sub-components** (bundled within libclamav.dll):
  - LZMA: GPL-2.0+
  - BZip2: bzip2 license
  - zlib: zlib license
  - PCRE: BSD-style
  - Jansson: MIT
  - c-thread-pool: MIT

---

## 4. LightGBM

- **License**: MIT License
- **Source**: https://github.com/microsoft/LightGBM
- **Usage**: Machine learning model for PE classification
- **Files**: `include/LightGBM/`, `lightgbm_objs.lib`, `lightgbm_capi_objs.lib`
- **Notice**:
  ```
  Copyright (c) Microsoft Corporation
  Licensed under the MIT License.
  ```

---

## 5. libarchive

- **License**: BSD-2-Clause
- **Source**: https://github.com/libarchive/libarchive
- **Usage**: Archive file extraction (ZIP, TAR, 7z, etc.)
- **Files**: `include/libarchive/`, `libarchive.lib`
- **Notice**:
  ```
  Copyright (c) 2003-2024...
  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in the
     documentation and/or other materials provided with the distribution.
  ```

---

## 6. Microsoft Detours

- **License**: Microsoft Research License
- **Source**: https://github.com/microsoft/Detours
- **Usage**: API hooking in TianHongDefense DLL
- **Files**: `detours.h`, `detours.lib`, `detours32.lib`
- **Note**: Microsoft Research License allows use in both research and commercial products with attribution.

---

## 7. OpenSSL

- **License**: OpenSSL License / SSLeay License
- **Source**: Via NuGet package `YARA.OpenSSL.x64`
- **Usage**: Cryptographic functions for YARA
- **Files**: `libssl.lib`, `libcrypto.lib` (in `packages/YARA.OpenSSL.x64/`)

---

## 8. Jansson

- **License**: MIT License
- **Source**: Via NuGet package `YARA.Jansson.x64`
- **Usage**: JSON parsing for YARA
- **Files**: `jansson.lib` (in `packages/YARA.Jansson.x64/`)

---

## 9. ElaWidgetTools

- **License**: To be confirmed with author
- **Source**: https://github.com/Ellise961/ElaWidgetTools
- **Usage**: Qt widget extension library
- **Files**: `ElaWidgetTools/`, `ElaWidgetTools.lib`
- **Note**: Please verify the license with the original author and update this notice accordingly.

---

## 10. bsdtar / libarchive components

Various compression libraries bundled with libarchive:
- **zlib**: zlib license (https://www.zlib.net/)
- **bzip2**: bzip2 license (https://www.bzip.org/)
- **LZMA SDK**: Public Domain (https://www.7-zip.org/sdk.html)
- **pcre**: BSD-style (https://www.pcre.org/)
- **minizip**: zlib license

---

## Summary

| Component | License | Compiles into | Distributed as |
|-----------|---------|---------------|----------------|
| Qt 6 | LGPL-3.0 / Commercial | Dynamic link | Pre-installed on system |
| YARA | Apache 2.0 / BSD-3 | Static lib | Source in repo + lib |
| ClamAV | GPL-2.0+ | Dynamic load | DLL shipped separately |
| LightGBM | MIT | Static lib | Headers + lib in repo |
| libarchive | BSD-2-Clause | Static lib | Source + lib in repo |
| Detours | MS Research | Static lib | Source + lib in repo |
| OpenSSL | OpenSSL | Static lib | NuGet package |
| Jansson | MIT | Static lib | NuGet package |
| ElaWidgetTools | TBD | Static lib | Source in repo |
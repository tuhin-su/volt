use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareProfile {
    pub name: String,
    pub hostname: String,
    pub machine_id: String,
    pub os_name: String,
    pub os_version: String,
    pub product_name: String,
    pub product_version: String,
    pub product_serial: String,
    pub product_uuid: String,
    pub board_vendor: String,
    pub board_name: String,
    pub board_version: String,
    pub board_serial: String,
    pub bios_vendor: String,
    pub bios_version: String,
    pub bios_date: String,
    pub chassis_type: String,
    pub cpu_model: String,
    pub cpu_cores: usize,
    pub mac_address: String,
}

impl HardwareProfile {
    /// Create standard VirtualBox template
    pub fn virtualbox() -> Self {
        let rand_hex = Uuid::new_v4().simple().to_string();
        let mac = format!(
            "08:00:27:{}:{}:{}",
            &rand_hex[0..2],
            &rand_hex[2..4],
            &rand_hex[4..6]
        );
        Self {
            name: "vm-virtualbox".to_string(),
            hostname: format!("VBOX-{}", &rand_hex[0..6].to_uppercase()),
            machine_id: Uuid::new_v4().simple().to_string(),
            os_name: "Ubuntu 24.04 LTS".to_string(),
            os_version: "24.04".to_string(),
            product_name: "VirtualBox".to_string(),
            product_version: "1.2".to_string(),
            product_serial: format!("VB{}", &rand_hex[0..10].to_uppercase()),
            product_uuid: Uuid::new_v4().to_string(),
            board_vendor: "Oracle Corporation".to_string(),
            board_name: "VirtualBox".to_string(),
            board_version: "1.2".to_string(),
            board_serial: format!("BS-{}", &rand_hex[10..18]),
            bios_vendor: "innotek GmbH".to_string(),
            bios_version: "VirtualBox".to_string(),
            bios_date: "12/01/2006".to_string(),
            chassis_type: "1".to_string(), // Other
            cpu_model: "Intel(R) Core(TM) i7-8700K CPU @ 3.70GHz".to_string(),
            cpu_cores: 4,
            mac_address: mac,
        }
    }

    /// Create standard Dell Latitude template
    pub fn dell_latitude() -> Self {
        let rand_hex = Uuid::new_v4().simple().to_string();
        let mac = format!(
            "b8:85:84:{}:{}:{}",
            &rand_hex[0..2],
            &rand_hex[2..4],
            &rand_hex[4..6]
        );
        Self {
            name: "laptop-dell".to_string(),
            hostname: format!("DESKTOP-{}", &rand_hex[0..7].to_uppercase()),
            machine_id: Uuid::new_v4().simple().to_string(),
            os_name: "Ubuntu 22.04.4 LTS".to_string(),
            os_version: "22.04".to_string(),
            product_name: "Latitude 5520".to_string(),
            product_version: "01".to_string(),
            product_serial: format!("7X{}", &rand_hex[0..5].to_uppercase()),
            product_uuid: Uuid::new_v4().to_string(),
            board_vendor: "Dell Inc.".to_string(),
            board_name: "0X9K12".to_string(),
            board_version: "A00".to_string(),
            board_serial: format!("/7X{}/CN12963/", &rand_hex[0..5].to_uppercase()),
            bios_vendor: "Dell Inc.".to_string(),
            bios_version: "1.28.0".to_string(),
            bios_date: "04/18/2023".to_string(),
            chassis_type: "10".to_string(), // Notebook
            cpu_model: "11th Gen Intel(R) Core(TM) i7-1185G7 @ 3.00GHz".to_string(),
            cpu_cores: 8,
            mac_address: mac,
        }
    }

    /// Create standard HP EliteDesk template
    pub fn hp_elitedesk() -> Self {
        let rand_hex = Uuid::new_v4().simple().to_string();
        let mac = format!(
            "9c:b6:54:{}:{}:{}",
            &rand_hex[0..2],
            &rand_hex[2..4],
            &rand_hex[4..6]
        );
        Self {
            name: "desktop-hp".to_string(),
            hostname: format!("HP-DESK-{}", &rand_hex[0..6].to_uppercase()),
            machine_id: Uuid::new_v4().simple().to_string(),
            os_name: "Debian GNU/Linux 12 (bookworm)".to_string(),
            os_version: "12".to_string(),
            product_name: "HP EliteDesk 800 G6 Small Form Factor PC".to_string(),
            product_version: "1.0".to_string(),
            product_serial: format!("CZC{}", &rand_hex[0..7].to_uppercase()),
            product_uuid: Uuid::new_v4().to_string(),
            board_vendor: "HP".to_string(),
            board_name: "870C".to_string(),
            board_version: "KBC Version 05.43.00".to_string(),
            board_serial: format!("PGT{}", &rand_hex[0..7].to_uppercase()),
            bios_vendor: "HP".to_string(),
            bios_version: "S01 Ver. 02.14.01".to_string(),
            bios_date: "10/12/2022".to_string(),
            chassis_type: "3".to_string(), // Desktop
            cpu_model: "Intel(R) Core(TM) i5-10500 CPU @ 3.10GHz".to_string(),
            cpu_cores: 6,
            mac_address: mac,
        }
    }

    /// Load by name or file path
    pub fn load_or_preset(name_or_path: &str) -> Result<Self> {
        let raw_path = Path::new(name_or_path);
        if raw_path.exists() {
            let content = fs::read_to_string(raw_path)
                .with_context(|| format!("Failed to read hardware profile at {:?}", raw_path))?;
            let profile: HardwareProfile = serde_json::from_str(&content)?;
            return Ok(profile);
        }

        // Check standard FHS share directories: /usr/local/share/volt/profiles, /usr/share/volt/profiles, ./profiles
        let candidate_dirs = [
            PathBuf::from("/usr/local/share/volt/profiles"),
            PathBuf::from("/usr/share/volt/profiles"),
            PathBuf::from("./profiles"),
        ];

        let json_name = if name_or_path.ends_with(".json") {
            name_or_path.to_string()
        } else {
            format!("{}.json", name_or_path)
        };

        for dir in &candidate_dirs {
            let candidate = dir.join(&json_name);
            if candidate.exists() {
                if let Ok(content) = fs::read_to_string(&candidate) {
                    if let Ok(profile) = serde_json::from_str::<HardwareProfile>(&content) {
                        return Ok(profile);
                    }
                }
            }
        }

        match name_or_path {
            "vm-virtualbox" | "virtualbox" | "vbox" => Ok(Self::virtualbox()),
            "laptop-dell" | "dell" => Ok(Self::dell_latitude()),
            "desktop-hp" | "hp" => Ok(Self::hp_elitedesk()),
            _ => Ok(Self::virtualbox()),
        }
    }

    /// Save profile to json file
    pub fn save_to<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        if let Some(parent) = path.as_ref().parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, json)?;
        Ok(())
    }

    /// Write all fake sysfs and procfs files into a target spoof directory
    pub fn write_spoof_tree<P: AsRef<Path>>(&self, target_dir: P) -> Result<PathBuf> {
        let base = target_dir.as_ref().to_path_buf();
        let sys_dmi = base.join("sys/class/dmi/id");
        let etc = base.join("etc");
        let proc = base.join("proc");

        fs::create_dir_all(&sys_dmi)?;
        fs::create_dir_all(&etc)?;
        fs::create_dir_all(&proc)?;

        // Write sysfs DMI files
        fs::write(
            sys_dmi.join("product_name"),
            format!("{}\n", self.product_name),
        )?;
        fs::write(
            sys_dmi.join("product_version"),
            format!("{}\n", self.product_version),
        )?;
        fs::write(
            sys_dmi.join("product_serial"),
            format!("{}\n", self.product_serial),
        )?;
        fs::write(
            sys_dmi.join("product_uuid"),
            format!("{}\n", self.product_uuid),
        )?;
        fs::write(
            sys_dmi.join("board_vendor"),
            format!("{}\n", self.board_vendor),
        )?;
        fs::write(sys_dmi.join("board_name"), format!("{}\n", self.board_name))?;
        fs::write(
            sys_dmi.join("board_version"),
            format!("{}\n", self.board_version),
        )?;
        fs::write(
            sys_dmi.join("board_serial"),
            format!("{}\n", self.board_serial),
        )?;
        fs::write(
            sys_dmi.join("bios_vendor"),
            format!("{}\n", self.bios_vendor),
        )?;
        fs::write(
            sys_dmi.join("bios_version"),
            format!("{}\n", self.bios_version),
        )?;
        fs::write(sys_dmi.join("bios_date"), format!("{}\n", self.bios_date))?;
        fs::write(
            sys_dmi.join("chassis_type"),
            format!("{}\n", self.chassis_type),
        )?;

        // Write etc files
        fs::write(etc.join("hostname"), format!("{}\n", self.hostname))?;
        fs::write(etc.join("machine-id"), format!("{}\n", self.machine_id))?;
        fs::write(
            etc.join("os-release"),
            format!(
                "NAME=\"{}\"\nVERSION=\"{}\"\nID=linux\nPRETTY_NAME=\"{} {}\"\n",
                self.os_name, self.os_version, self.os_name, self.os_version
            ),
        )?;

        // Write fake /etc/hosts (mapping localhost, spoofed hostname, and current host hostname)
        let host_hostname = nix::unistd::gethostname()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|_| "localhost".to_string());
        let hosts_content = format!(
            "127.0.0.1\tlocalhost {} {}\n::1\t\tlocalhost ip6-localhost ip6-loopback {} {}\n",
            self.hostname, host_hostname, self.hostname, host_hostname
        );
        fs::write(etc.join("hosts"), hosts_content)?;

        // Write fake /proc/cpuinfo
        let mut cpuinfo = String::new();
        for i in 0..self.cpu_cores {
            cpuinfo.push_str(&format!(
                "processor\t: {}\nmodel name\t: {}\ncpu MHz\t\t: 2600.000\ncache size\t: 12288 KB\nphysical id\t: 0\nsiblings\t: {}\ncore id\t\t: {}\ncpu cores\t: {}\n\n",
                i, self.cpu_model, self.cpu_cores, i, self.cpu_cores
            ));
        }
        fs::write(proc.join("cpuinfo"), cpuinfo)?;

        // Write fake /proc/version
        fs::write(
            proc.join("version"),
            format!("Linux version 6.8.0-45-generic (buildd@lcy02) (x86_64-linux-gnu-gcc) #45-Ubuntu SMP PREEMPT\n"),
        )?;

        // Write fake /etc/passwd (with root as investigator)
        fs::write(
            etc.join("passwd"),
            "root:x:0:0:root:/root:/bin/bash\ninvestigator:x:1000:1000:Investigator:/home/investigator:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n",
        )?;

        // Write fake /etc/shadow
        fs::write(
            etc.join("shadow"),
            "root:*:19000:0:99999:7:::\ninvestigator:*:19000:0:99999:7:::\nnobody:*:19000:0:99999:7:::\n",
        )?;

        Ok(base)
    }
}

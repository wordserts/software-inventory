"""
Software Inventory Extension
Monitors installed programs from Windows Registry, Linux package managers, and macOS Homebrew
"""

import platform
import socket

from datetime import datetime, timedelta
from typing import List, Dict, Optional
import json 
import os

if platform.system() == 'Windows':
    try:
        import winreg  
    except ImportError:
        raise ImportError("winreg module is required on Windows platforms")
elif platform.system() == 'Linux':
    try:
        import distro 
        import subprocess
    except ImportError:
        raise ImportError("distro and subprocess modules are required on Linux platforms")    
else:
    raise ImportError("Unsupported platform for this extension")


try:
    from dynatrace_extension import Extension, Status, StatusValue

except ImportError:
    # Fallback for local testing
    class Extension:
        config = {}
        logger = None
        def __init__(self):
            self.config = {}
            self.logger = None
        def run(self):
            pass
    class Status:
        def __init__(self, status, message=""):
            self.status = status
            self.message = message
    class StatusValue:
        OK = "OK"
        ERROR = "ERROR"


#
# Class that checks the software inventory
#
class SoftwareInventoryExtension(Extension):
    """Extension to monitor installed programs from various package managers"""

    os_platform = platform.system()
    brew_installed = False
    brew_path = None
    config = {}
    linux_flavour = None
    linux_version = None
    supported_linux = ['ubuntu', 'debian', 'centos', 'rhel', 'fedora']
    dnf_based = ['fedora', 'rhel', 'centos']
    apt_based = ['ubuntu', 'debian']
    hostname = None

    def initialize(self):
        """Initialize the extension"""
        
        try:
            # Get hostname
            self.hostname = socket.gethostname()
            self.logger.info(f"Running on host: {self.hostname}")
            
            self.collection_interval = 60  # Default to 60 minutes
            collection_interval_str = "60"
            if hasattr(self.config, 'get'):
                # Config is a dict-like object
                collection_interval_str =  self.config.get("collection_interval", "60")
            else:
                # Config might be an object with attributes
                collection_interval_str = getattr(self.config, 'collection_interval', "60")

            try:            
                self.collection_interval = int(collection_interval_str)
            except (ValueError, TypeError):
                self.collection_interval = 60

            self.logger.info(f"Collection Interval: {self.collection_interval} minutes")

            #  Platform-specific initialization
            if self.os_platform == 'Windows':
                self._initialise_windows()
            elif self.os_platform == 'Linux':
                self._initialise_linux()
            
            # schedule based on collection_interval my custom query method
            self.schedule(self.query_packages, timedelta(minutes=self.collection_interval))
            
        except Exception as e:
            self.logger.error(f"Error in initialize: {e}", exc_info=True)
            raise

    def _initialise_linux(self):
        self.linux_flavour = distro.id()
        self.linux_version = distro.version()
        self.logger.info(f"Linux Distribution: {self.linux_flavour} Version: {self.linux_version}")
        # check if not supported
        if self.linux_flavour not in self.supported_linux:
            self.logger.warning(f"Linux distribution {self.linux_flavour} is not supported by this extension.")
            raise Exception(f"Unsupported Linux distribution: {self.linux_flavour}")
        # Currently no implementation for Linux installed programs

    def _initialise_brew(self):
        self.logger.info("Initializing macOS Software Inventory Extension")
        # Looking at brew for a start
        # todo - Applications folder and other package managers
        try:
            # brew_path_macos
            self.brew_path = self._get_brew_path()
            self.logger.info(f"Brew Path: {self.brew_path}")
            # check if brew_path is not None
            if self.brew_path:
                self.brew_installed = True
                self.logger.info(f"Homebrew found at: {self.brew_path}")
            else:
                self.logger.info("Homebrew not found on this system.")

        except Exception as e:
            self.logger.warning(f"Error accessing config, using defaults: {e}")
            registry_path_32bit = ""
            registry_path_64bit = ""
            exclude_updates_str = "true"

    def _initialise_windows(self):
        self.logger.info("Initializing Windows Registry Software Inventory Extension")
            
        # Safely get configuration - handle both dict and object access
        try:
            if hasattr(self.config, 'get'):
                # Config is a dict-like object
                registry_path_32bit = self.config.get("registry_path_32bit", "")
                registry_path_64bit = self.config.get("registry_path_64bit", "")
                exclude_updates_str = self.config.get("exclude_windows_updates", "true")
            else:
                # Config might be an object with attributes
                registry_path_32bit = getattr(self.config, 'registry_path_32bit', "")
                registry_path_64bit = getattr(self.config, 'registry_path_64bit', "")
                exclude_updates_str = getattr(self.config, 'exclude_windows_updates', "true")
        except Exception as e:
            self.logger.warning(f"Error accessing config, using defaults: {e}")
            registry_path_32bit = ""
            registry_path_64bit = ""
            exclude_updates_str = "true"
        
        # Set defaults if empty
        self.registry_path_32bit = registry_path_32bit if registry_path_32bit else \
            "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
        
        self.registry_path_64bit = registry_path_64bit if registry_path_64bit else \
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
         
        # Exclude Windows Updates (handle as string from config)
        self.exclude_windows_updates = str(exclude_updates_str).lower() in ['true', 'yes', '1']
        
        self.logger.info(f"Configured to monitor: {self.registry_path_64bit} and {self.registry_path_32bit}")
        self.logger.info(f"Exclude Windows Updates: {self.exclude_windows_updates}")
        

    def query_packages(self):
        """Main query method called by OneAgent"""
        try:
            if self.os_platform == 'Windows':
                self._query_windows()
            elif self.os_platform == 'Linux':
                self._query_linux()
            
        except Exception as e:
            self.logger.error(f"Error querying installed programs: {str(e)}", exc_info=True)
            return Status(StatusValue.ERROR, f"Failed to query: {str(e)}")
    
    def _query_brew(self):
        self.logger.info("Querying macOS installed packages")
        if self.brew_installed:
            self.logger.info("Querying macOS Homebrew installed packages")
            try:
                programs = self._get_installed_brew()
                self._report_metrics_nix(programs, "brew")
                
            except subprocess.CalledProcessError as e:
                self.logger.error(f"Error querying Homebrew: {str(e)}", exc_info=True)
                return Status(StatusValue.ERROR, f"Failed to query Homebrew: {str(e)}")

    def _query_linux(self):
        self.logger.info("Querying Linux installed packages")
        # Currently no implementation for Linux installed programs
        if self.linux_flavour in self.apt_based:
            self.logger.info("Querying APT-based packages")
            try:
                programs = self._get_installed_apt()
                self._report_metrics_nix(programs, "apt")
                
            except subprocess.CalledProcessError as e:
                self.logger.error(f"Error querying APT packages: {str(e)}", exc_info=True)
                return Status(StatusValue.ERROR, f"Failed to query APT packages: {str(e)}")
        elif self.linux_flavour in self.dnf_based:
            self.logger.info("Querying DNF-based packages")
            try:
                programs = self._get_installed_dnf()
                self._report_metrics_nix(programs, "dnf")
                
            except subprocess.CalledProcessError as e:
                self.logger.error(f"Error querying DNF packages: {str(e)}", exc_info=True)
                return Status(StatusValue.ERROR, f"Failed to query DNF packages: {str(e)}")

    def _query_windows(self):
        """Query Windows registry for installed programs"""
        try:
            self.logger.info("Starting Windows registry query")
            
            # Get programs from both registry paths
            programs_64 = self._get_installed_programs(winreg.HKEY_LOCAL_MACHINE, 
                                                      self.registry_path_64bit,
                                                      "64-bit")
            programs_32 = self._get_installed_programs(winreg.HKEY_LOCAL_MACHINE,
                                                      self.registry_path_32bit,
                                                      "32-bit")
            
            # Combine and deduplicate programs
            all_programs = programs_64 + programs_32
            
            # Remove duplicates based on program name and version
            unique_programs = {}
            for program in all_programs:
                key = (program['program_name'], program['program_version'])
                if key not in unique_programs:
                    unique_programs[key] = program
            
            programs = list(unique_programs.values())
            
            self.logger.info(f"Found {len(programs)} unique programs ({len(programs_64)} 64-bit, {len(programs_32)} 32-bit)")
            
            # Report metrics
            self._report_metrics(programs)
            
            return Status(StatusValue.OK, f"Successfully queried {len(programs)} programs")
            
        except Exception as e:
            self.logger.error(f"Error querying Windows registry: {str(e)}", exc_info=True)
            return Status(StatusValue.ERROR, f"Failed to query: {str(e)}")

    def _get_installed_programs(self, hkey, registry_path: str, arch: str) -> List[Dict]:
        """Get installed programs from a specific registry path"""
        programs = []
        
        try:
            registry_key = winreg.OpenKey(hkey, registry_path)
            
            # Iterate through all subkeys
            i = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(registry_key, i)
                    
                    # Skip Windows Updates if configured
                    if self.exclude_windows_updates and subkey_name.startswith('KB'):
                        i += 1
                        continue
                    
                    try:
                        subkey = winreg.OpenKey(registry_key, subkey_name)
                        
                        # Get program details
                        program_name = self._get_registry_value(subkey, "DisplayName")
                        
                        # Skip if no display name (system components)
                        if not program_name:
                            winreg.CloseKey(subkey)
                            i += 1
                            continue
                        
                        program = {
                            'program_name': program_name,
                            'program_version': self._get_registry_value(subkey, "DisplayVersion", ""),
                            'program_publisher': self._get_registry_value(subkey, "Publisher", ""),
                            'install_location': self._get_registry_value(subkey, "InstallLocation", ""),
                            'install_date': self._format_install_date(
                                self._get_registry_value(subkey, "InstallDate", "")
                            ),
                            'architecture': arch
                        }
                        
                        programs.append(program)
                        winreg.CloseKey(subkey)
                        
                    except WindowsError:
                        # Skip subkeys we can't access
                        pass
                    
                    i += 1
                    
                except OSError:
                    # No more subkeys
                    break
            
            winreg.CloseKey(registry_key)
            
        except WindowsError as e:
            self.logger.warning(f"Could not open registry key {registry_path}: {e}")
        
        return programs

    def _get_registry_value(self, key, value_name: str, default: str = None) -> Optional[str]:
        """Safely get a value from registry key"""
        try:
            value, _ = winreg.QueryValueEx(key, value_name)
            return str(value) if value else default
        except WindowsError:
            return default

    def _report_metrics(self, programs: List[Dict]):
        """Report metrics to Dynatrace"""
        try:
            # Report total count
            self.report_metric(
                key="software_inventory.programs.count",
                value=len(programs),
                dimensions={'host.name': self.hostname}
            )
            
            # Report individual program metrics with dimensions
            for program in programs:
                dimensions = {
                    'host.name': self.hostname,
                    'program_name': self._sanitize_dimension(program.get('program_name', 'Unknown')),
                    'program_version': self._sanitize_dimension(program.get('program_version', '')),
                    'program_publisher': self._sanitize_dimension(program.get('program_publisher', '')),
                    'install_location': self._sanitize_dimension(program.get('install_location', '')),
                    'install_date': self._sanitize_dimension(program.get('install_date', ''))
                }
                
                self.report_metric(
                    key="software_inventory.programs.info",
                    value=1,
                    dimensions=dimensions
                )
            
            self.logger.info(f"Successfully reported metrics for {len(programs)} programs")
            
        except Exception as e:
            self.logger.error(f"Error reporting metrics: {e}", exc_info=True)

    def _report_metrics_nix(self, programs: List[Dict], package_manager: str):
        """Report metrics to Dynatrace for Linux/macOS packages"""
        try:
            # Report total count
            self.report_metric(
                key="software_inventory.programs.count",
                value=len(programs),
                dimensions={'host.name': self.hostname}
            )
            
            # Report individual program metrics with dimensions
            for program in programs:
                dimensions = {
                    'host.name': self.hostname,
                    'program_name': self._sanitize_dimension(program.get('program_name', 'Unknown')),
                    'program_version': self._sanitize_dimension(program.get('program_version', '')),
                    'program_publisher': self._sanitize_dimension(program.get('program_publisher', '')),
                    'install_location': self._sanitize_dimension(program.get('install_location', '')),
                    'install_date': self._sanitize_dimension(program.get('install_date', ''))
                }
                
                self.report_metric(
                    key=f"software_inventory.programs.info",
                    value=1,
                    dimensions=dimensions
                )
            
            self.logger.info(f"Successfully reported metrics for {len(programs)} {package_manager}-based programs")
            
        except Exception as e:
            self.logger.error(f"Error reporting {package_manager}-based metrics: {e}", exc_info=True)

    def _sanitize_dimension(self, value: str) -> str:
        """Sanitize dimension values for Dynatrace"""
        if not value:
            return ''
        # Strip whitespace
        sanitized = value.strip()
        # Replace backslashes with forward slashes (Windows paths cause parsing errors)
        sanitized = sanitized.replace('\\', '/')
        # Remove quotes that can break parsing
        sanitized = sanitized.replace('"', '')
        sanitized = sanitized.replace("'", '')
        # Remove any other problematic characters
        sanitized = sanitized.replace('\n', ' ')
        sanitized = sanitized.replace('\r', ' ')
        sanitized = sanitized.replace('\t', ' ')
        # Limit length
        return sanitized[:200]

    def _create_entity_id(self, name: str) -> str:
        """Create a valid entity ID from program name"""
        # Replace spaces and special characters with underscores
        entity_id = ''.join(c if c.isalnum() else '_' for c in name)
        # Remove consecutive underscores
        entity_id = '_'.join(filter(None, entity_id.split('_')))
        return entity_id.lower()

    def _format_install_date(self, date_str: str) -> str:
        """Format install date from registry format (YYYYMMDD) to readable format"""
        if not date_str or len(date_str) != 8:
            return date_str
        
        try:
            # Convert YYYYMMDD to YYYY-MM-DD
            return f"{date_str[0:4]}-{date_str[4:6]}-{date_str[6:8]}"
        except:
            return date_str

    def _get_installed_apt(self):
        programs = []
        try:
            result = subprocess.run(
                ['dpkg-query', '-W', '-f=${Package}\t${Version}\t${Maintainer}\t${Installed-Size}\n'],
                capture_output=True,
                text=True,
                check=True
            )
            for line in result.stdout.splitlines():
                parts = line.split('\t')
                if len(parts) >= 3:
                    program = {
                        'program_name': parts[0],
                        'program_version': parts[1],
                        'program_publisher': parts[2],
                        'install_location': 'Unknown',
                        'install_date': 'Unknown'
                    }
                    programs.append(program)
            return programs
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error getting APT packages: {e}")

    def _get_installed_dnf(self):
        programs = []
        try:
            result = subprocess.run(
                ['rpm', '-qa', '--queryformat', '%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\t%{SIZE}\t%{INSTALLTIME:date}\n'],
                capture_output=True,
                text=True,
                check=True
            )
            for line in result.stdout.splitlines():
                parts = line.split('\t')
                if len(parts) >= 3:
                    date_parts = parts[4].rsplit(' ', 1)[0]  # Remove timezone (AEDT)
                    dt = datetime.strptime(date_parts, '%a %d %b %Y %I:%M:%S %p')
                    install_date = dt.strftime('%Y-%m-%d')
                    program = {
                        'program_name': parts[0],
                        'program_version': parts[1],
                        'program_publisher': parts[2] if parts[2] else 'Unknown',
                        'install_location': 'Unknown',
                        'install_date': install_date
                    }
                    programs.append(program)
            return programs
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error getting RPM packages: {e}")
            return programs

    def _get_brew_path(self):
        # Get the path to brew executable using 'which' command
        try:
            result = subprocess.run(
                ['which', 'brew'],
                capture_output=True,
                text=True,
                check=True
            )
            brew_path = result.stdout.strip()
            return brew_path if brew_path else None
        except subprocess.CalledProcessError:
            return None
        
    def _get_installed_brew(self):
        programs = []
        brew_prefix = self.brew_path
        try:
            result = subprocess.run(
                ['brew', 'info', '--json=v2', '--installed'],
                capture_output=True,
                text=True,
                check=True
            )
            data = json.loads(result.stdout)
            
            for formula in data.get('formulae', []):
                program = {
                    'program_name': formula['name'],
                    'program_version': 'Unknown',
                    'program_publisher': 'Unknown',
                    'install_location': 'Unknown',
                    'install_date': 'Unknown'
                }
                
                # Get version
                if formula.get('installed'):
                    program['program_version'] = formula['installed'][0].get('version', 'Unknown')
                
                # Get publisher (from homepage or tap)
                homepage = formula.get('homepage', '')
                if homepage:
                    from urllib.parse import urlparse
                    parsed = urlparse(homepage)
                    program['program_publisher'] = parsed.netloc.replace('www.', '')
                else:
                    # Use tap as publisher if no homepage
                    tap = formula.get('tap', 'homebrew/core')
                    program['program_publisher'] = tap.split('/')[0]
                
                # Get install location
                cellar_path = os.path.join(brew_prefix, 'Cellar', formula['name'])
                if os.path.exists(cellar_path):
                    program['install_location'] = cellar_path
                    
                    # Get install date from directory
                    try:
                        version_dirs = os.listdir(cellar_path)
                        if version_dirs:
                            version_path = os.path.join(cellar_path, version_dirs[0])
                            mtime = os.path.getmtime(version_path)
                            program['install_date'] = datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S')
                    except Exception:
                        pass
                
                programs.append(program)
            return(programs)
        except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
            print(f"Error getting formulae: {e}")


def main():
    """Entry point for the extension"""
    SoftwareInventoryExtension().run()


if __name__ == '__main__':
    main()

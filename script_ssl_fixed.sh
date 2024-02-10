#!/bin/bash

# Log file location
log_file="/var/log/script.log"

# Function to log messages
log() {
    local message="$1"
    echo "$(date +"%Y-%m-%d %H:%M:%S") - $message" | sudo tee -a "$log_file"
}

# Create the log file and set permissions
sudo touch "$log_file"
sudo chmod 644 "$log_file"
log "Log file created and permissions set."

# Function to check if the OS is Ubuntu and version is 22.04 or above
is_supported_ubuntu_version() {
    if [ -n "$(lsb_release -a 2>/dev/null | grep 'Ubuntu')" ]; then
        ubuntu_version=$(lsb_release -r | awk '{print $2}')
        if [ "$(echo "$ubuntu_version >= 22.04" | bc)" -eq 1 ]; then
            return 0
        fi
    fi
    return 1
}

# Function to check if the script is run with root privileges
is_root() {
    if [ "$EUID" -eq 0 ]; then
        return 0
    fi
    return 1
}

# Function to install dependencies
install_dependencies() {
    log "Installing dependencies..."
    iptables -A INPUT -p tcp --dport 80 -j ACCEPT &&  iptables -A INPUT -p tcp --dport 22 -j ACCEPT &&  iptables -A INPUT -p tcp --dport 443 -j ACCEPT
    sudo apt update
    sudo apt install -y lsb-release curl mysql-client certbot iptables curl wget sudo nano zip ufw
    log "Dependencies installed."
    sleep 3
    clear
}

# Function to display IP information
ipinfo() {
    curl -s ifconfig.me
}

# Ask the user for the domain name
get_domain_name() {
    read -p "Enter the domain name: " domain_name
}


# Function to prompt user for confirmation
confirm() {
    read -p "Type 'yes' to make sure your $domain_name and IP are not proxied in Cloudflare (Auto SSL): " response
    if [ "$response" != "yes" ]; then
        echo "Aborted. Make sure your domain and IP are not proxied in Cloudflare."
        exit 1
    fi
    sleep 3
    clear
}

# Function to flush iptables rules and allow port 22, 80, 443
iptables_flush() {
    #echo -e "\e[92mFlushing iptables rules and allowing ports 22, 80, 443...\e[0m"

    # Flush existing rules
    iptables -F && iptables -A INPUT -p tcp --dport 22 -j ACCEPT && iptables -A INPUT -p tcp --dport 80 -j ACCEPT && iptables -A INPUT -p tcp --dport 443 -j ACCEPT
    
    sleep 3
    clear
}
#Fetch cloudflare IPs
fetch_cloudflare_ips() {
    url="https://www.cloudflare.com/ips-v4/"
    ip_ranges=$(curl -s "$url")
    echo "$ip_ranges"
}

# Function to install RainLoop Webmail
install_rainloop() {
    echo -e "\e[92mOnly use subddomain for RainLoop installation (like webmail.domain.com)...\e[0m"
    
    get_domain_name  # Ask the user for the domain name
    
    confirm #Ask for cloudflare non proxied domain that point to IP
    
    #iptables_flush  # Flush iptables rules and allow essential ports

    echo -e "\e[92mCreating a directory for RainLoop installation...\e[0m"
    sudo mkdir /var/www/$domain_name
    sudo chown -R www-data:www-data /var/www/$domain_name
    echo -e "\e[92mCreating Apache virtual host configuration...\e[0m"
    vhost_file="/etc/apache2/sites-available/$domain_name.conf"

    echo "<VirtualHost *:80>
    ServerName $domain_name
    ServerAlias www.$domain_name

    DocumentRoot /var/www/$domain_name

    RewriteCond %{HTTP_HOST} !^www.
    RewriteCond %{HTTPS}s on(s)|offs()
    RewriteRule ^ http%1://www.%{HTTP_HOST}%{REQUEST_URI} [NE,L,R]

    ErrorLog \${APACHE_LOG_DIR}/$domain_name_error.log
    CustomLog \${APACHE_LOG_DIR}/$domain_name_access.log combined
    <Directory /var/www/$domain_name>
        Options -Indexes +FollowSymLinks +MultiViews
        AllowOverride All
        Require all granted
    </Directory>
    # Block access to the 'data' directory
    <Directory /var/www/$domain_name/data>
        Order deny,allow
        Deny from all
    </Directory>
    # For PHP 8.2
    <FilesMatch \.php$>
        SetHandler \"proxy:unix:/run/php/php8.2-fpm.sock|fcgi://localhost/\"
    </FilesMatch>
    </VirtualHost>" | sudo tee $vhost_file

    clear
    curl -sL https://repository.rainloop.net/installer.php -o /var/www/$domain_name/installer.php
    
    # Navigate to the directory
    cd /var/www/$domain_name
    
    
    sudo a2dissite /etc/apache2/sites-enabled/000-default.conf

    # Run the RainLoop installer script using PHP
    sudo php installer.php

    echo -e "\e[92mEnabling the new virtual host...\e[0m"
    sudo a2ensite $domain_name.conf

    echo -e "\e[92mRestarting Apache...\e[0m"
    sudo systemctl restart apache2

    echo -e "\e[92mInstalling RainLoop...\e[0m"
    cd /var/www/$domain_name
    

    echo -e "\e[92mUpdating /etc/hosts file for domain name resolution...\e[0m"
    echo "$(ipinfo)" "$domain_name" | sudo tee -a /etc/hosts
    echo "$(ipinfo)" www."$domain_name" | sudo tee -a /etc/hosts

    echo -e "\e[92mObtaining SSL certificate from Let's Encrypt...\e[0m"
    
    # Clear existing rules & Allow SSH & Block all HTTP and HTTPS Trafic
    #iptables -F && iptables -A INPUT -p tcp --dport 22,80,443/tcp -j ACCEPT

    #Getting SSL
    sudo certbot --apache -d $domain_name -d www."$domain_name" -m admin@$domain_name --agree-tos


    echo -e "\e[92mRainLoop installation complete.\e[0m"
    sleep 5
}

# Function to install Shopware
install_shopware() {
    get_domain_name  # Ask the user for the domain name

    #iptables_flush  # Flush iptables rules and allow essential ports

    confirm #Ask for cloudflare non proxied domain that point to IP
    
    echo -e "\e[92mInstalling Shopware 6...\e[0m"

    sudo apt update && sudo apt upgrade -y

    echo -e "\e[92mInstalling necessary packages...\e[0m"
    sudo apt install -y apache2 mariadb-server certbot python3-certbot-apache php-fpm php-mysql php-curl php-dom php-json php-zip php-gd php-xml php-mbstring php-intl php-opcache

    sudo add-apt-repository ppa:ondrej/php
    sudo apt install php8.2 -y
    sudo apt install php8.2-fpm php8.2-common php8.2-mysql php8.2-xml php8.2-xmlrpc php8.2-curl php8.2-gd php8.2-imagick php8.2-cli php8.2-dev php8.2-imap php8.2-mbstring php8.2-opcache php8.2-soap php8.2-zip php8.2-intl -y

    sudo apt install mariadb-server -y
    sudo systemctl unmask maridb
    sudo systemctl restart mariadb

    sudo apt install -y curl
    curl -fsSL https://raw.githubusercontent.com/weltmonster/Shopware6Installer/main/script.sh | sudo -E bash -
    sudo apt install -y nodejs npm
    sudo sed -i 's/memory_limit = .*/memory_limit = 2048M/' /etc/php/8.2/fpm/php.ini
    sudo sed -i 's/upload_max_filesize = .*/upload_max_filesize = 20M/' /etc/php/8.2/fpm/php.ini
    sudo sed -i 's/max_execution_time = .*/max_execution_time = 300/' /etc/php/8.2/fpm/php.ini
    sudo mkdir -p /var/www/$domain_name
    sudo wget https://github.com/shopware/web-recovery/releases/latest/download/shopware-installer.phar.php -P /var/www/$domain_name
    sudo chown -R www-data:www-data /var/www/$domain_name
    sudo chmod -R 755 /var/www/$domain_name
    vhost_file="/etc/apache2/sites-available/$domain_name.conf"
    echo "<VirtualHost *:80>
    ServerName $domain_name
    ServerAlias www.$domain_name

    ServerAdmin webmaster@$domain_name
    DocumentRoot /var/www/$domain_name

    RewriteCond %{HTTP_HOST} !^www.
    RewriteCond %{HTTPS}s on(s)|offs()
    RewriteRule ^ http%1://www.%{HTTP_HOST}%{REQUEST_URI} [NE,L,R]

    ErrorLog \${APACHE_LOG_DIR}/$domain_name_error.log
    CustomLog \${APACHE_LOG_DIR}/$domain_name_access.log combined

    <Directory /var/www/$domain_name>
        Options -Indexes +FollowSymLinks +MultiViews
        AllowOverride All
        Order allow,deny
        allow from all
    </Directory>

    #Redirect requests from the /public URL path to /
    RewriteEngine On
    RewriteRule ^/public(/.*)?$ /$1 [R=301,L]

    # For PHP 8.2
    <FilesMatch \.php$>
        SetHandler \"proxy:unix:/run/php/php8.2-fpm.sock|fcgi://localhost/\"
    </FilesMatch>

</VirtualHost>" | sudo tee $vhost_file

    sudo a2dissite /etc/apache2/sites-enabled/000-default.conf
    sudo a2ensite $domain_name.conf
    sudo a2enmod rewrite
    sudo a2enmod proxy_fcgi setenvif
    sudo sed -i 's/;opcache.memory_consumption=.*/opcache.memory_consumption=256/' /etc/php/8.2/cli/php.ini
    sudo sed -i 's/;opcache.memory_consumption=.*/opcache.memory_consumption=256/' /etc/php/8.2/fpm/php.ini
    sudo sed -i 's/memory_limit =.*/memory_limit = 2048M/' /etc/php/8.2/cli/php.ini
    sudo systemctl restart php8.2-fpm
    sudo systemctl restart apache2
    echo "$(ipinfo)" "$domain_name" | sudo tee -a /etc/hosts
    echo "$(ipinfo)" www."$domain_name" | sudo tee -a /etc/hosts

    
    # Clear existing rules & Allow SSH & Block all HTTP and HTTPS Trafic
    #iptables -F && iptables -A INPUT -p tcp --dport 22,80,443/tcp -j ACCEPT

    #Getting SSL
    sudo certbot --apache -d $domain_name -d www."$domain_name" -m admin@$domain_name --agree-tos

    db_password=$(openssl rand -base64 12)
    echo -e "\e[92mCreating database and user...\e[0m"
    sudo mysql -uroot -e "CREATE DATABASE shopware;"
    sudo mysql -uroot -e "CREATE USER shopware@'localhost' IDENTIFIED BY '$db_password';"
    sudo mysql -uroot -e "GRANT ALL PRIVILEGES ON shopware.* TO shopware@'localhost';"
    sudo mysql -uroot -e "FLUSH PRIVILEGES;"
    echo -e "\e[92mRestarting Apache one more time...\e[0m"
    sudo systemctl restart apache2
    while true; do
    #clear
    echo "Type 'yes' to confirm successful installation of Shopware 1st installer at https://$domain_name/shopware-installer.phar.php/install (until you get Forbidden 403 Error) "
    read -p " " response
    if [ "$response" == "yes" ]; then
        break
    else
        echo "Please type 'yes' to confirm the successful installation."
    fi
    done
    #clear
    
    while true; do
        echo "After the first installer, press 'yes' to remove the 'public' after $domain_name that is not changeable after installation"
        
        # Update the configuration files
        sudo sed -i "s|DocumentRoot /var/www/$domain_name|DocumentRoot /var/www/$domain_name/public|g" /etc/apache2/sites-available/$domain_name-le-ssl.conf
        sudo sed -i "s|DocumentRoot /var/www/$domain_name|DocumentRoot /var/www/$domain_name/public|g" /etc/apache2/sites-available/$domain_name.conf
        
        # Restart Apache
        sudo systemctl restart apache2
        #clear

        # Print DB Details
        echo -e "\e[92mDatabase Name: shopware\e[0m"
        echo -e "\e[92mDatabase User: shopware\e[0m"
        echo -e "\e[92mDatabase Password: $db_password\e[0m"

        # Create the credentials.txt file
        echo -e "# Print DB Details\nDatabase Name: shopware\nDatabase User: shopware\nDatabase Password: $db_password" > /root/credentials.txt

        # Inform the user that the file has been created
        echo "Credentials have been saved in credentials.txt"
        sleep 5
        break
    done
    echo "After getting Forbidden Error Refresh the Web page."
    echo -e "\e[92mChanges have been made. You can access the 2nd Shopware installer at https://$domain_name/shopware-installer.phar.php\e[0m"

    while true; do
        read -p "After installing Shopware from the 2nd installer, press 'y': " user_input
        if [ "$user_input" == "y" ]; then
            break
        fi
    done

}

# Function to set up Cloudflare access
cloudflare_setup() {
clear
echo -e "\e[92mSetting up Cloudflare access for $domain_name...\e[0m"

while true; do
    read -p "Type 'y' to make sure your $domain_name and IP are proxied in Cloudflare to prevent IP leaks: " user_input
    if [ "$user_input" == "y" ]; then
        break
    fi
done

#Enable and disable UFW
ufw enable
ufw disable

# Fetch Cloudflare IP ranges
cloudflare_ips=$(fetch_cloudflare_ips)

# Clear existing Cloudflare rules (optional)
iptables -F

#Allow SSH & Block all HTTP and HTTPS Trafic
iptables -A INPUT -p tcp --dport 22 -j ACCEPT && iptables -A INPUT -p tcp --dport 80 -j DROP && iptables -A INPUT -p tcp --dport 443 -j DROP

# Allow incoming traffic from Cloudflare IP ranges in iptables
while IFS= read -r ip_range; do
    iptables -A INPUT -p tcp --dport 80 -s "$ip_range" -j ACCEPT
    iptables -A INPUT -p tcp --dport 443 -s "$ip_range" -j ACCEPT
done <<< "$cloudflare_ips"

iptables-save
iptables-legacy-save

echo -e "\e[92mCloudflare access setup completed for $domain_name.\e[0m"

}


# Main script
#Root permission check

if ! is_root; then
    echo "This script requires root privileges. Please run it with sudo."
    exit 1
fi
# Check the OS and it's version 
if ! is_supported_ubuntu_version; then
    echo "This script is designed to run on Ubuntu 22.4 or above only."
    exit 1
fi

PS3="Select an option: "
options=("Install Shopware" "Install Shopware with RainLoop Webmail" "Quit")
select option in "${options[@]}"; do
    case $REPLY in
    1)
        log "Starting Shopware installation."
        install_dependencies  # Install dependencies
        log "Dependencies installed."
        install_shopware
        log "Shopware installation completed."
        #log "Starting cloudflare setup."
        #cloudflare_setup      # Setup cloudflare
        #log "Cloudflare setup Completed"
        exit
        ;;
    2)
        log "Dependencies logs Start."
        install_dependencies  # Install dependencies
        log "Dependencies installed."
        log "Starting Shopware installation."
        install_shopware      # Install shopware6
        log "Shopware installation completed."
        log "Starting RainLoop Webmail installation."
        install_rainloop      # Install webmail_rainloop
        log "RainLoop Webmail installation completed."
        #log "Starting cloudflare setup."
        #cloudflare_setup      # setup cloudflare
        #log "Cloudflare setup Completed"
        exit
        ;;
    3)
        log "Script terminated."
        exit
        ;;
    *)
        log "Invalid option. Please select a valid option."
        ;;
    esac
done

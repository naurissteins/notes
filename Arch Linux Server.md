## Install Arch Linux Server (phpMyadmin, MariaDB, php8, nginx, redis)

#### Add users
`sudo useradd --create-home user`

#### Add password
`sudo passwd user`

### Sudo premissions for users
`EDITOR=vim visudo`
<sub>uncomment #%wheel ALL=(ALL) ALL</sub>

#### Add to wheel group (sudo user)
`usermod -aG wheel user`

#### Create a website directory
```
sudo mkdir -p /home/user/www/example.com/log
sudo mkdir -p /home/user/www/example.com/html
```
#### Directory premission
```
sudo chown -R user:user /home/user/www/
sudo chmod -R 0755 /home/user/www/
```

### Install nginx
```
sudo pacman -S nginx-mainline
sudo systemctl enable --now nginx
sudo systemctl status nginx
```

### Install mariadb
```
sudo pacman -S mariadb
sudo mariadb-install-db --user=mysql --basedir=/usr --datadir=/var/lib/mysql
sudo systemctl enable --now mariadb
```
`sudo mysql_secure_installation` # Enter N N Y Y Y

### Add SQL user
*User*
```
CREATE USER 'user'@'%' IDENTIFIED BY 'passwor';
GRANT ALL PRIVILEGES ON `ns\_%` .  * TO 'ns'@'%';
FLUSH PRIVILEGES;
```
*Superuser (admin)*
```
CREATE USER 'user'@'%' IDENTIFIED BY 'password';
GRANT ALL PRIVILEGES ON *.* TO 'user'@localhost IDENTIFIED BY 'password';
FLUSH PRIVILEGES;
```

#### Install php
```
sudo pacman -S php php-fpm php-gd
sudo systemctl enable --now php-fpm
```

### Edit php.ini /etc/php7/php.ini
*uncomment*
```
extension=curl
extension=gd
extension=soap
extension=iconv
extension=mysqli
zend_extension=opcache
extension=zip
extension=exif
extension=pdo_mysql
```
*uncomment*
```
[OPCache]
opcache.enable=1
opcache.enable_cli=0
opcache.memory_consumption=128
opcache.interned_strings_buffer=8
opcache.max_accelerated_files=40000
```

### Change SSH port
```
sudo nvim /etc/ssh/sshd_config
sudo systemctl restart sshd
```

### Install crontjob
```
sudo pacman -S pacman-contrib
sudo systemctl enable --now cronie
sudo systemctl status cronie
EDITOR=vim crontab -e
```

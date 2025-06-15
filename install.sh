#!/bin/bash
#
# cert-manager - Скрипт для получения и автоматического обновления SSL-сертификатов.
#

# --- Переменные и Настройки ---
SCRIPT_NAME="cert-manager"
INSTALL_PATH="/usr/local/bin/${SCRIPT_NAME}"
DEFAULT_HOOK_COMMAND="systemctl reload nginx"
# Имя для нашего хук-скрипта, который будет объединять PEM файлы
PEM_COMBINER_HOOK_SCRIPT="/etc/letsencrypt/renewal-hooks/deploy/01-cert-manager-pem-combiner"
# URL для обновления скрипта
GITHUB_RAW_URL="https://raw.githubusercontent.com/xxphantom/cert-manager/main/install.sh"

# Цвета для вывода
C_RESET='\033[0m'
C_RED='\033[0;31m'
C_GREEN='\033[0;32m'
C_YELLOW='\033[0;33m'
C_BLUE='\033[0;34m'
C_WHITE='\033[1;37m'

# --- Вспомогательные функции ---
msg_info() { echo -e "${C_BLUE}[INFO]${C_RESET} $1"; }
msg_ok() { echo -e "${C_GREEN}[OK]${C_RESET} $1"; }
msg_warn() { echo -e "${C_YELLOW}[WARN]${C_RESET} $1"; }
msg_error() { echo -e "${C_RED}[ERROR]${C_RESET} $1"; }

check_root() {
  if [[ $EUID -ne 0 ]]; then
    echo -e "${C_RED}[ERROR]${C_RESET} Этот скрипт должен быть запущен с правами root. Используйте 'sudo'."
    exit 1
  fi
}

press_enter_to_continue() {
  echo ""
  read -p "Нажмите [Enter] для продолжения..."
}

is_script_installed() {
  [ -f "$INSTALL_PATH" ]
}

check_port_80() {
  if ! command -v ufw &>/dev/null; then
    msg_warn "UFW не установлен. Считаем, что порт 80 открыт."
    return 0
  fi

  if ufw status | grep -qw "Status: inactive"; then
    msg_warn "UFW неактивен. Считаем, что порт 80 открыт."
    return 0
  fi
  if ufw status | grep -qE "^\s*80(/tcp)?\s+ALLOW"; then
    return 0
  fi
  return 1
}

create_combined_pem_for_domain() {
  local domain=$1
  local cert_dir="/etc/letsencrypt/live/${domain}"

  if [ ! -d "$cert_dir" ]; then
    msg_error "Директория сертификата для домена ${domain} не найдена."
    return 1
  fi

  local combined_pem_path="${cert_dir}/full.pem"
  msg_info "Создание объединенного файла ${C_YELLOW}${combined_pem_path}${C_RESET}..."

  cat "${cert_dir}/privkey.pem" "${cert_dir}/fullchain.pem" >"${combined_pem_path}"

  if [ $? -eq 0 ]; then
    msg_ok "Объединенный файл ${C_WHITE}full.pem${C_RESET} успешно создан."
  else
    msg_error "Не удалось создать объединенный файл ${C_WHITE}full.pem${C_RESET}."
  fi
}

# Создает и устанавливает deploy-hook для Certbot.
# Этот хук будет автоматически объединять файлы при каждом обновлении сертификата.
create_and_install_deploy_hook() {
  if [ -f "$PEM_COMBINER_HOOK_SCRIPT" ]; then
    # Хук уже существует, ничего делать не нужно
    return 0
  fi

  msg_info "Установка хука для автоматического создания объединенных .pem файлов..."
  mkdir -p "$(dirname "$PEM_COMBINER_HOOK_SCRIPT")" || {
    msg_error "Не удалось создать директорию для хука."
    return 1
  }

  # Используем heredoc для создания скрипта-хука
  cat <<'EOF' >"$PEM_COMBINER_HOOK_SCRIPT"
#!/bin/bash
#
# Этот скрипт автоматически выполняется Certbot после успешного обновления сертификата.
# Он объединяет приватный ключ (privkey.pem) и полную цепочку сертификатов (fullchain.pem)
# в один файл (full.pem), который требуется некоторым приложениям (например, HAProxy).
# Скрипт установлен и управляется cert-manager'ом.

set -e # Прерывать выполнение при любой ошибке

# Certbot передает путь к директории сертификата через переменную RENEWED_LINEAGE
if [ -n "$RENEWED_LINEAGE" ]; then
    DOMAIN_DIR="$RENEWED_LINEAGE"
    COMBINED_PEM_PATH="${DOMAIN_DIR}/full.pem"

    echo "Hook: Combining certs for ${DOMAIN_DIR}"

    # Проверяем наличие файлов
    if [ ! -f "${DOMAIN_DIR}/privkey.pem" ] || [ ! -f "${DOMAIN_DIR}/fullchain.pem" ]; then
        echo "Hook: Error - Certificate files not found in ${DOMAIN_DIR}"
        exit 1
    fi

    # Объединяем ключ и цепочку
    cat "${DOMAIN_DIR}/privkey.pem" "${DOMAIN_DIR}/fullchain.pem" > "${COMBINED_PEM_PATH}"

    echo "Hook: Successfully created combined PEM file at ${COMBINED_PEM_PATH}"
fi

exit 0
EOF

  chmod +x "$PEM_COMBINER_HOOK_SCRIPT"
  if [ $? -eq 0 ]; then
    msg_ok "Deploy-хук для объединения PEM-файлов успешно установлен."
  else
    msg_error "Не удалось установить deploy-хук."
  fi
}

# --- Основные функции (с изменениями и без) ---

install_dependencies() {
  msg_info "Проверка и установка зависимостей..."
  local missing_packages=""
  for pkg_cmd in certbot:certbot ufw:ufw curl:curl dig:dnsutils cron:cron; do
    local cmd=${pkg_cmd%%:*}
    local pkg=${pkg_cmd##*:}
    if ! command -v "$cmd" &>/dev/null; then
      missing_packages+="$pkg "
    fi
  done
  if ! dpkg -l | grep -q 'python3-certbot-dns-cloudflare'; then
    missing_packages+="python3-certbot-dns-cloudflare "
  fi
  if [ -n "$missing_packages" ]; then
    msg_info "Обновление списка пакетов..."
    apt-get update -y || {
      msg_error "Не удалось обновить список пакетов"
      return 1
    }
    msg_info "Установка недостающих пакетов: ${missing_packages}"
    apt-get install -y $missing_packages || {
      msg_error "Не удалось установить пакеты"
      return 1
    }
    msg_ok "Все зависимости установлены."
  else
    msg_ok "Зависимости уже установлены."
  fi
}

get_hook_command() {
  local domain=$1
  local renewal_conf="/etc/letsencrypt/renewal/${domain}.conf"
  if [ -f "$renewal_conf" ]; then
    grep 'renew_hook' "$renewal_conf" | cut -d'=' -f2- | sed 's/^[ \t]*//;s/[ \t]*$//'
  fi
}

update_renewal_conf_hook() {
  local domain=$1
  local hook_command=$2
  local renewal_conf="/etc/letsencrypt/renewal/${domain}.conf"

  if [ ! -f "$renewal_conf" ]; then
    msg_error "Файл конфигурации для домена ${domain} не найден."
    return 1
  fi

  # Удаляем старую строку с хуком
  sed -i '/^renew_hook/d' "$renewal_conf"

  if [ -n "$hook_command" ]; then
    # Этап 1: Сначала экранируем обратные слэши.
    # Это важно делать первым, чтобы не экранировать слэши, которые мы добавим на следующих этапах.
    local sanitized_hook_command="${hook_command//\\/\\\\}"

    # Этап 2: Экранируем амперсанды.
    sanitized_hook_command="${sanitized_hook_command//&/\\&}"

    # Этап 3: Экранируем наш разделитель `|`.
    sanitized_hook_command="${sanitized_hook_command//|/\\|}"

    # Используем полностью экранированную команду в sed
    sed -i "s|^\(\[renewalparams\]\)|\1\nrenew_hook = ${sanitized_hook_command}|" "$renewal_conf"
  fi
}

interactive_set_hook_for_domain() {
  local domain=$1
  if [ -z "$domain" ]; then return 1; fi

  local current_hook
  current_hook=$(get_hook_command "$domain")

  echo -e "\n--- Настройка хука для домена: ${C_WHITE}${domain}${C_RESET} ---"
  echo "Этот хук (renew_hook) выполняется после обновления для перезапуска служб."
  echo "Примеры: systemctl reload nginx, docker restart my_container, /path/to/my/script.sh"
  echo "Чтобы удалить хук, оставьте поле пустым."

  read -p "Введите команду хука: " -e -i "${current_hook:-$DEFAULT_HOOK_COMMAND}" new_command

  update_renewal_conf_hook "$domain" "$new_command"
  msg_ok "Хук для домена ${C_WHITE}${domain}${C_RESET} установлен на: ${C_YELLOW}${new_command:-[не установлен]}${C_RESET}"
}

ensure_cron_job_exists() {
  if ! crontab -l 2>/dev/null | grep -q '/usr/bin/certbot renew'; then
    msg_info "Настройка ежедневной проверки обновления в cron..."
    (
      crontab -l 2>/dev/null
      echo "0 4 * * * /usr/bin/certbot renew --quiet"
    ) | crontab -
    msg_ok "Задача для certbot renew добавлена в cron."
  fi
}

set_hook_command() {
  clear
  echo "--- Настройка команды-хука для домена ---"

  local domains_array=()
  if [ -d "/etc/letsencrypt/live" ]; then
    for cert_dir in /etc/letsencrypt/live/*; do
      if [ -d "$cert_dir" ]; then
        domains_array+=("$(basename "$cert_dir")")
      fi
    done
  fi

  if [ ${#domains_array[@]} -eq 0 ]; then
    msg_warn "Сертификаты не найдены. Не для чего настраивать хук."
    press_enter_to_continue
    return
  fi

  echo "Выберите домен для настройки хука:"
  for i in "${!domains_array[@]}"; do
    local domain="${domains_array[$i]}"
    local current_hook
    current_hook=$(get_hook_command "$domain")
    echo -e "  ${C_YELLOW}$((i + 1)).${C_RESET} ${domain} ${C_BLUE}[${current_hook:-не установлен}]${C_RESET}"
  done
  echo -e "  ${C_YELLOW}0.${C_RESET} Назад"
  read -p "Ваш выбор: " choice

  if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 0 ] || [ "$choice" -gt ${#domains_array[@]} ]; then
    msg_error "Неверный выбор."
    press_enter_to_continue
    return
  fi

  if [ "$choice" -eq 0 ]; then return; fi

  local selected_domain="${domains_array[$((choice - 1))]}"
  interactive_set_hook_for_domain "$selected_domain"

  press_enter_to_continue
}

get_cert_cloudflare() {
  read -p "Введите ваш домен (например, example.com): " domain
  read -p "Введите ваш email для Let's Encrypt: " email
  read -s -p "Введите ваш Cloudflare API токен: " cf_token
  echo
  if [ -z "$domain" ] || [ -z "$email" ] || [ -z "$cf_token" ]; then
    msg_error "Все поля обязательны для заполнения."
    press_enter_to_continue
    return 1
  fi
  local base_domain=$(echo "$domain" | awk -F'.' '{if (NF > 2) {print $(NF-1)"."$NF} else {print $0}}')
  local wildcard_domain="*.${base_domain}"
  msg_info "Создание файла с учетными данными Cloudflare..."
  mkdir -p /etc/letsencrypt/cloudflare
  echo "dns_cloudflare_api_token = ${cf_token}" >/etc/letsencrypt/cloudflare/credentials.ini
  chmod 600 /etc/letsencrypt/cloudflare/credentials.ini
  msg_info "Запрос Wildcard-сертификата для ${wildcard_domain}..."
  certbot certonly \
    --dns-cloudflare --dns-cloudflare-credentials /etc/letsencrypt/cloudflare/credentials.ini \
    -d "$base_domain" -d "$wildcard_domain" --email "$email" --agree-tos --non-interactive \
    --key-type ecdsa --elliptic-curve secp384r1

  if [ $? -eq 0 ]; then
    msg_ok "Сертификат для ${base_domain} успешно получен!"
    ensure_cron_job_exists
    create_and_install_deploy_hook
    create_combined_pem_for_domain "$base_domain"
    interactive_set_hook_for_domain "$base_domain"
  else
    msg_error "Не удалось получить сертификат."
  fi
  press_enter_to_continue
}

get_cert_acme() {
  read -p "Введите ваш домен (например, panel.example.com): " domain
  read -p "Введите ваш email для Let's Encrypt: " email
  if [ -z "$domain" ] || [ -z "$email" ]; then
    msg_error "Все поля обязательны для заполнения."
    press_enter_to_continue
    return 1
  fi
  local server_ip=$(curl -s -4 ifconfig.me)
  local domain_ip=$(dig +short A "$domain" | head -n 1)
  msg_info "IP сервера: ${server_ip}"
  msg_info "IP домена ${domain}: ${domain_ip}"
  if [ "$server_ip" != "$domain_ip" ]; then
    msg_warn "IP-адрес домена не совпадает с IP-адресом сервера."
    read -p "Продолжить? (y/n): " confirm
    if [[ "$confirm" != "y" ]]; then
      msg_error "Операция отменена."
      press_enter_to_continue
      return 1
    fi
  fi
  msg_info "Проверка доступности порта 80 для проверки ACME..."
  if ! check_port_80; then
    msg_error "Порт 80/tcp закрыт в UFW или недоступен."
    msg_warn "Вы можете открыть его командой: ${C_YELLOW}sudo ufw allow 80/tcp${C_RESET}"
    msg_error "Операция отменена."
    press_enter_to_continue
    return 1
  fi
  msg_ok "Порт 80/tcp доступен для проверки."
  msg_info "Запрос сертификата для ${domain}..."
  certbot certonly --standalone -d "$domain" --email "$email" --agree-tos --non-interactive \
    --http-01-port 80 --key-type ecdsa --elliptic-curve secp384r1

  if [ $? -eq 0 ]; then
    msg_ok "Сертификат для ${domain} успешно получен!"
    ensure_cron_job_exists
    create_and_install_deploy_hook
    create_combined_pem_for_domain "$domain"
    interactive_set_hook_for_domain "$domain"
  else
    msg_error "Не удалось получить сертификат."
  fi
  press_enter_to_continue
}

get_certificate() {
  clear
  echo "--- Получение нового сертификата ---"
  install_dependencies
  echo "Выберите способ получения сертификата:"
  echo -e "  ${C_YELLOW}1.${C_RESET} Cloudflare API (рекомендуется, поддерживает wildcard)"
  echo -e "  ${C_YELLOW}2.${C_RESET} Стандартный ACME (требует открытый порт 80, без wildcard)"
  echo -e "  ${C_YELLOW}0.${C_RESET} Назад"

  read -p "Ваш выбор [1-2, 0]: " choice

  case $choice in
  1) get_cert_cloudflare ;;
  2) get_cert_acme ;;
  0) return ;;
  *)
    msg_error "Неверный выбор."
    press_enter_to_continue
    ;;
  esac
}

show_status() {
  clear
  echo "--- Статус SSL-сертификатов ---"
  if ! command -v certbot &>/dev/null; then
    msg_warn "Certbot не установлен. Нечего показывать."
    press_enter_to_continue
    return
  fi
  if [ ! -d "/etc/letsencrypt/live" ] || [ -z "$(ls -A /etc/letsencrypt/live)" ]; then
    msg_info "Сертификаты не найдены."
    press_enter_to_continue
    return
  fi

  msg_info "Найденные сертификаты и их статус:"

  for cert_dir in /etc/letsencrypt/live/*; do
    if [ -d "$cert_dir" ]; then
      domain=$(basename "$cert_dir")
      echo -e "\n${C_WHITE}Домен: ${domain}${C_RESET}"
      echo -e "  Сертификат (fullchain): ${C_YELLOW}${cert_dir}/fullchain.pem${C_RESET}"
      echo -e "  Приватный ключ:         ${C_YELLOW}${cert_dir}/privkey.pem${C_RESET}"

      # Проверяем и выводим путь к объединенному файлу
      local combined_pem_path="${cert_dir}/full.pem"
      if [ -f "$combined_pem_path" ]; then
        echo -e "  Объединенный файл:      ${C_GREEN}${combined_pem_path}${C_RESET}"
      else
        echo -e "  Объединенный файл:      ${C_RED}не найден${C_RESET} (будет создан при следующем обновлении)"
      fi

      expiry_date=$(openssl x509 -in "${cert_dir}/fullchain.pem" -noout -enddate | cut -d= -f2)
      expiry_epoch=$(date -d "$expiry_date" +%s)
      current_epoch=$(date +%s)
      days_left=$(((expiry_epoch - current_epoch) / 86400))

      if [ "$days_left" -lt 14 ]; then color=$C_RED; elif [ "$days_left" -lt 30 ]; then color=$C_YELLOW; else color=$C_GREEN; fi
      echo -e "  Срок действия: ${color}${days_left} дней${C_RESET} (до ${expiry_date})"

      hook_command=$(get_hook_command "$domain")
      echo -e "  Хук перезапуска: ${C_YELLOW}${hook_command:-[не установлен]}${C_RESET}"
    fi
  done

  press_enter_to_continue
}

force_renew() {
  clear
  echo "--- Принудительное обновление сертификатов ---"

  local domains_array=()
  if [ -d "/etc/letsencrypt/live" ]; then
    for cert_dir in /etc/letsencrypt/live/*; do
      if [ -d "$cert_dir" ]; then
        domains_array+=("$(basename "$cert_dir")")
      fi
    done
  fi

  if [ ${#domains_array[@]} -eq 0 ]; then
    msg_warn "Сертификаты не найдены. Нечего обновлять."
    press_enter_to_continue
    return
  fi

  echo "Выберите сертификат для принудительного обновления:"
  echo -e "  ${C_YELLOW}1.${C_RESET} Обновить ${C_WHITE}ВСЕ${C_RESET} сертификаты"
  echo "  -----------------------------------"
  for i in "${!domains_array[@]}"; do
    echo -e "  ${C_YELLOW}$((i + 2)).${C_RESET} ${domains_array[$i]}"
  done
  echo -e "  ${C_YELLOW}0.${C_RESET} Назад в главное меню"

  read -p "Ваш выбор: " choice

  if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 0 ] || [ "$choice" -gt $((${#domains_array[@]} + 1)) ]; then
    msg_error "Неверный выбор."
    press_enter_to_continue
    return
  fi

  if [ "$choice" -eq 0 ]; then
    return
  fi

  local target_domain=""
  local target_display_name=""

  if [ "$choice" -eq 1 ]; then
    target_domain="all"
    target_display_name="ВСЕХ сертификатов"
  else
    target_domain="${domains_array[$((choice - 2))]}"
    target_display_name="сертификат для домена ${target_domain}"
  fi

  echo
  msg_warn "Принудительное обновление обычно не требуется. Certbot автоматически обновляет сертификаты за 30 дней до истечения срока."
  msg_warn "Частое использование этой функции может привести к исчерпанию лимитов Let's Encrypt для вашего домена."

  echo -en "Вы уверены, что хотите принудительно обновить ${target_display_name}? (y/n): "
  read confirm

  if [[ "${confirm,,}" != "y" ]]; then
    msg_info "Операция отменена."
    press_enter_to_continue
    return
  fi

  # Перед обновлением убедимся, что наш хук для объединения PEM на месте
  create_and_install_deploy_hook

  if [ "$target_domain" == "all" ]; then
    msg_info "Запуск принудительного обновления всех сертификатов..."
    certbot renew --force-renewal
  else
    msg_info "Запуск принудительного обновления для домена ${C_WHITE}${target_domain}${C_RESET}..."
    certbot renew --force-renewal --cert-name "$target_domain"
  fi

  msg_ok "Процесс обновления завершен. Проверьте вывод на наличие ошибок."
  press_enter_to_continue
}

install_script() {
  clear
  local action_text="Установка"
  local success_text="установлен"

  if is_script_installed; then
    action_text="Обновление"
    success_text="обновлен"
    echo "--- Обновление скрипта ---"
    msg_info "Скачивание последней версии с GitHub..."

    # Создаем временный файл
    local temp_file=$(mktemp)

    # Скачиваем последнюю версию
    if curl -fsSL "$GITHUB_RAW_URL" -o "$temp_file"; then
      msg_ok "Последняя версия скачана."
      msg_info "Обновление скрипта в ${INSTALL_PATH}..."
      cp "$temp_file" "$INSTALL_PATH"
      chmod +x "$INSTALL_PATH"
      rm -f "$temp_file"
    else
      msg_error "Не удалось скачать обновление с GitHub."
      rm -f "$temp_file"
      press_enter_to_continue
      return 1
    fi
  else
    echo "--- Установка скрипта ---"
    msg_info "Установка скрипта в ${INSTALL_PATH}..."
    cp "${BASH_SOURCE[0]}" "$INSTALL_PATH"
    chmod +x "$INSTALL_PATH"
  fi

  if [ -f "$INSTALL_PATH" ]; then
    msg_ok "Скрипт успешно ${success_text}. Теперь вы можете вызывать его командой '${SCRIPT_NAME}'."
  else
    msg_error "Ошибка ${action_text,,}а."
  fi
  press_enter_to_continue
}

# === ОБНОВЛЕННАЯ ФУНКЦИЯ МЕНЮ ===
show_menu() {
  clear
  local install_text="Установить/обновить этот скрипт"
  if is_script_installed; then
    install_text="Обновить этот скрипт"
  fi

  echo -e "${C_WHITE}=======================================${C_RESET}"
  echo -e "  ${C_GREEN}Менеджер SSL-сертификатов (cert-manager)${C_RESET}"
  echo -e "${C_WHITE}=======================================${C_RESET}"
  echo -e " ${C_YELLOW}1.${C_RESET} Показать статус сертификатов"
  echo -e " ${C_YELLOW}2.${C_RESET} Получить новый сертификат"
  echo -e " ${C_YELLOW}3.${C_RESET} Принудительное обновление сертификата(ов)"
  echo -e " ${C_YELLOW}4.${C_RESET} Настроить команду-хук для домена"
  echo ""
  echo -e " ${C_YELLOW}9.${C_RESET} ${install_text}"
  echo -e " ${C_YELLOW}0.${C_RESET} Выход"
  echo -e "${C_WHITE}=======================================${C_RESET}"
  read -p "Выберите опцию: " choice
}

main_menu() {
  while true; do
    show_menu
    case $choice in
    1) show_status ;;
    2) get_certificate ;;
    3) force_renew ;;
    4) set_hook_command ;;
    9) install_script ;;
    0)
      echo "Выход."
      exit 0
      ;;
    *)
      msg_error "Неверный выбор. Попробуйте еще раз."
      sleep 1
      ;;
    esac
  done
}

check_root

if [ $# -gt 0 ]; then
  case "$1" in
  get) get_certificate ;;
  status) show_status ;;
  renew) force_renew ;;
  sethook) set_hook_command ;;
  install) install_script ;;
  *) echo "Неизвестная команда. Запустите без аргументов для входа в меню." ;;
  esac
else
  main_menu
fi

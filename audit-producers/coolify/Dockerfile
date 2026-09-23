FROM coollabsio/coolify:4.3.23
USER root
WORKDIR /var/www/html
COPY base-files.sha256 operations.patch /tmp/platform-audit/
RUN sha256sum -c /tmp/platform-audit/base-files.sha256 \
 && git apply --check /tmp/platform-audit/operations.patch \
 && git apply /tmp/platform-audit/operations.patch \
 && php -l app/Support/PlatformOperationAudit.php \
 && php -l app/Providers/AppServiceProvider.php \
 && php -l app/Jobs/ApplicationDeploymentJob.php \
 && php -l bootstrap/helpers/applications.php \
 && rm -rf /tmp/platform-audit
USER www-data

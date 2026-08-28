# SG InfoSec Implementation Roadmap

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement each detailed plan task-by-task.

**Goal:** Разбить утверждённую архитектуру SG InfoSec на независимые, проверяемые и последовательно поставляемые части.

**Spec:** `docs/superpowers/specs/2026-08-28-sg-infosec-design.md`

## План 1 — Core MVP

Файл: `docs/superpowers/plans/2026-08-28-sg-infosec-core-mvp.md`

Результат: непривилегированный Go-демон, который принимает структурированные события через Unix-сокет, определяет источник по peer credentials, хранит данные в SQLite, применяет политики, создаёт прикладные решения и предоставляет локальный control API и CLI. Firewall отсутствует; решения проверяются через локальный API.

## План 2 — nftables Enforcer

Результат: отдельный минимальный root-демон, владеющий только таблицей `inet sg_infosec`, применяющий типизированные решения для отдельных сервисных портов и выполняющий reconciliation с SQLite.

Зависимость: План 1.

## План 3 — SG-Gateway backend integration

Результат: безопасная отправка `auth.failed` и `api.auth_failed`, trusted-proxy определение реального IP, fail-open middleware только для административных маршрутов и contract tests, подтверждающие отсутствие влияния на подписки и VPN.

Зависимость: План 1. План 2 нужен только для SSH и других портовых scope, но не для административных маршрутов SG-Gateway.

## План 4 — Debian packaging and lifecycle

Результат: Debian-пакеты, systemd socket/service units, users/groups, конфигурация, update, migration, backup, restore, uninstall и purge с сохранением чужих firewall-правил и состояния SG-Gateway.

Зависимости: Планы 1 и 2.

## План 5 — SG-Gateway Security UI and system validation

Результат: раздел «Безопасность», управление решениями, allowlist и политиками через control API, аудит действий, системные тесты на Ubuntu 22.04/24.04 и ресурсные проверки на VM с 1 ГиБ RAM.

Зависимости: Планы 1–4 и backend-интеграция из Плана 3.

## Порядок поставки

1. Core MVP.
2. SG-Gateway backend integration без UI — ранняя проверка прикладной модели блокировок.
3. nftables Enforcer.
4. Debian packaging and lifecycle.
5. Security UI and full system validation.

Такой порядок позволяет получить рабочую защиту административного входа до добавления root-компонента и отдельно проверить, что подписки и VPN не затрагиваются.

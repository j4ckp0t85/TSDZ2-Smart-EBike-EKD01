/* Host regression tests of the actual firmware functions, including UART output.
 * Hardware-only entry points are stubbed and must not execute in these tests.
 * See _INTERNALDOCS/battery-soc-verification.md for commands and boundaries.
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#define __CDT_PARSER__
#define __interrupt(x)
#define __asm__(x)
#define __trap
#include "../src/config.h"
#ifdef TEST_EKD01_SOC_PERCENT_MODE
#undef EKD01_SOC_PERCENT_MODE
#define EKD01_SOC_PERCENT_MODE TEST_EKD01_SOC_PERCENT_MODE
#endif
#include "../src/ebike_app.c"
#include "../src/common.c"

volatile uint16_t ui16_adc_voltage;
volatile uint16_t ui16_adc_voltage_cut_off;
volatile uint8_t ui8_battery_SOC_saved_flag;
volatile uint8_t ui8_battery_SOC_reset_flag;
volatile uint8_t ui8_g_duty_cycle;
volatile uint8_t ui8_brake_state;
volatile uint16_t ui16_adc_throttle;
volatile uint8_t ui8_controller_duty_cycle_ramp_up_inverse_step;
volatile uint8_t ui8_controller_duty_cycle_ramp_down_inverse_step;
volatile uint8_t ui8_adc_battery_current_filtered;
volatile uint8_t ui8_controller_adc_battery_current_target;
volatile uint8_t ui8_fw_hall_counter_offset;
volatile uint16_t ui16_hall_counter_total;
volatile uint8_t ui8_controller_duty_cycle_target;
volatile uint16_t ui16_adc_torque;
volatile uint16_t ui16_cadence_sensor_ticks;
volatile uint16_t ui16_wheel_speed_sensor_ticks;

void motor_enable_pwm(void) { assert(!"Unexpected motor PWM call"); }
void motor_disable_pwm(void) { assert(!"Unexpected motor PWM call"); }
void EEPROM_controller(uint8_t operation, uint8_t initial_byte)
{
    (void)operation;
    (void)initial_byte;
    assert(!"Unexpected EEPROM write");
}
void lights_set_state(uint8_t state) { (void)state; assert(!"Unexpected lights call"); }

static uint8_t sent[UART_TX_BUFFER_LEN];
static unsigned int sent_count;

#if EKD01_SOC_PERCENT_MODE
#define TEST_FULL_BATTERY_VALUE 100U
#else
#define TEST_FULL_BATTERY_VALUE 12U
#endif

int uart_put_char(int c)
{
    assert(sent_count < sizeof(sent));
    sent[sent_count++] = (uint8_t)c;
    return c;
}

static void boot(uint8_t saved, uint8_t mode, uint16_t adc)
{
    memset((void *)&m_configuration_variables, 0, sizeof(m_configuration_variables));
    m_configuration_variables.ui8_battery_SOC_percentage_8b = saved;
    m_configuration_variables.ui8_soc_percent_calculation = mode;
    m_configuration_variables.ui16_battery_low_voltage_cut_off_x10 = 390;
    m_configuration_variables.ui16_wheel_perimeter = WHEEL_PERIMETER;
    ui8_battery_voltage_initialized = 0;
    ui8_battery_soc_initialized = 0;
    ui8_battery_SOC_reset_flag = 0;
    ui8_battery_SOC_saved_flag = 0;
    ui8_battery_state_of_charge = 0;
    ui8_startup_counter = 0;
    ui8_startup_flag = 0;
    ui8_display_ready_flag = 1;
    ui16_adc_battery_voltage_accumulated = 0;
    ui16_battery_voltage_filtered_x10 = 0;
    ui16_battery_voltage_calibrated_and_filtered_x10 = 0;
    ui16_battery_current_filtered_soc_x10 = 0;
    ui16_battery_soc_pull_counter = 0;
    ui8_battery_current_filtered_x10 = 0;
    ui8_adc_battery_current_filtered = 0;
    ui8_g_duty_cycle = 0;
    ui16_actual_battery_capacity = TARGET_MAX_BATTERY_CAPACITY * ACTUAL_BATTERY_CAPACITY_PERCENT / 100;
    ui32_wh_x10 = 0;
    ui32_wh_offset_x10 = 0;
    ui32_wh_sum_x10 = 0;
    ui32_wh_since_power_on_x10 = 0;
    ui16_battery_power_x10 = 0;
    ui8_working_status = 0;
    ui8_system_state = NO_ERROR;
    ui8_display_function_code = NO_FUNCTION;
    ui8_display_data_enabled = 0;
    ui8_display_data_on_startup = 0;
    ui8_menu_index = 0;
    ui8_menu_counter = 0;
    ui16_oem_wheel_speed_time = 0x0707;
    ui16_adc_voltage = adc;
    sent_count = 0;
    ebike_app_init();
}

static uint8_t send_level(void)
{
    unsigned int i;
    uint8_t checksum = 0;
    sent_count = 0;
    uart_send_package();
    assert(UART_TX_BUFFER_LEN == 9U);
    assert(sent_count == UART_TX_BUFFER_LEN);
    for (i = 0; i < TX_CHECK_CODE; ++i) checksum += sent[i];
    assert(sent[TX_CHECK_CODE] == checksum);
    assert(sent[0] == TX_STX);
    // SOC must not be smuggled into speed, power, or protocol status bits.
    assert(sent[6] == 0x07 && sent[7] == 0x07);
    assert((sent[2] & 0x0a) == 0);
#if EKD01_SOC_PERCENT_MODE
    assert(sent[1] == (ui16_battery_SOC_percentage_x10 >= 1000U ? 100U :
        (ui16_battery_SOC_percentage_x10 + 5U) / 10U));
#endif
    return sent[1];
}

static void tick(void)
{
    unsigned int i;
    for (i = 0; i < 4; ++i) get_battery_voltage();
    calc_watt_hours_used();
    check_battery_soc();
}

static void test_startup(void)
{
    unsigned int i;
    uint16_t first_soc, first_voltage;
    uint8_t first_level;
    boot(100, SOC_CALC_AUTO, 0);
    tick();
    uart_send_package();
    assert(sent_count == 0); // ADC not ready: no invented empty/full frame.
    assert(!ui8_battery_soc_initialized);
    ui16_adc_voltage = 630; // about 54.8 V at the configured 87 mV/step
    tick();
    first_voltage = ui16_battery_voltage_calibrated_and_filtered_x10;
    assert(first_voltage == 630U * BATTERY_VOLTAGE_PER_10_BIT_ADC_STEP_X1000 / 100U);
    assert(ui16_battery_SOC_percentage_x10 == 1000);
    assert(send_level() == TEST_FULL_BATTERY_VALUE);
    for (i = 0; i < 100; ++i) {
        tick();
        assert(ui16_battery_voltage_calibrated_and_filtered_x10 == first_voltage);
        assert(ui16_battery_SOC_percentage_x10 == 1000);
        assert(send_level() == TEST_FULL_BATTERY_VALUE);
    }
    assert(ui8_startup_flag); // menu startup still completes

    // Uninitialized EEPROM and a partial charge: first transmitted reading
    // already matches the voltage curve and never rises while filters settle.
    boot(0, SOC_CALC_AUTO, 550);
    tick();
    first_soc = ui16_battery_SOC_percentage_x10;
    first_voltage = ui16_battery_voltage_calibrated_and_filtered_x10;
    first_level = send_level();
    assert(first_soc > 100 && first_soc < 900);
    for (i = 0; i < 100; ++i) {
        tick();
        assert(ui16_battery_SOC_percentage_x10 == first_soc);
        assert(ui16_battery_voltage_calibrated_and_filtered_x10 == first_voltage);
        assert(send_level() == first_level);
    }
    // Invalid EEPROM cannot underflow the energy offset to a huge number.
    boot(255, SOC_CALC_AUTO, 550);
    tick();
    assert(ui16_battery_SOC_percentage_x10 == first_soc);

    // Full ADC range: target-width multiplication must not wrap above 65.5 V.
    boot(0, SOC_CALC_VOLTS, 1023);
    tick();
    assert(ui16_battery_voltage_filtered_x10 == 1023UL * BATTERY_VOLTAGE_PER_10_BIT_ADC_STEP_X1000 / 100);
    assert(ui16_battery_SOC_percentage_x10 == 1000);
}

static void test_saved_charge_and_modes(void)
{
    unsigned int mode, i;
    uint16_t first_soc;
    for (mode = SOC_CALC_AUTO; mode <= SOC_CALC_VOLTS; ++mode) {
        boot(125, (uint8_t)mode, 550);
        tick();
        first_soc = ui16_battery_SOC_percentage_x10;
        if (mode == SOC_CALC_WH) assert(first_soc >= 500 && first_soc <= 501);
        if (mode == SOC_CALC_VOLTS) assert(first_soc == read_battery_soc());
        for (i = 0; i < 100; ++i) {
            tick();
            assert(ui16_battery_SOC_percentage_x10 == first_soc);
        }
    }
    // A saved SOC close to the rested-voltage estimate is retained in Auto.
    boot(130, SOC_CALC_AUTO, 550);
    tick();
    assert(ui16_battery_SOC_percentage_x10 >= 520 && ui16_battery_SOC_percentage_x10 <= 521);
    // A saved SOC more than 10 pp from it is corrected at power on.
    boot(150, SOC_CALC_AUTO, 550);
    tick();
    // Energy offset round trip may differ by 0.1 pp.
    assert(ui16_battery_SOC_percentage_x10 + 1U >= read_battery_soc() && ui16_battery_SOC_percentage_x10 <= read_battery_soc() + 1U);
    assert(ui16_battery_SOC_percentage_x10 < 500);
    // Charging while switched off resets even an otherwise retained Wh gauge.
    boot(75, SOC_CALC_WH, 630);
    tick();
    assert(ui16_battery_SOC_percentage_x10 == 1000);
    assert(ui32_wh_offset_x10 == 0);
}

static void test_power_on_after_light_use(void)
{
    unsigned int mode, i;
    // ADC 615 is about 53.5 V (4.12 V/cell): above the 4.10 V reset voltage, below charger level.
    assert(615U * BATTERY_VOLTAGE_PER_10_BIT_ADC_STEP_X1000 / 100U >= BATTERY_VOLTAGE_RESET_SOC_PERCENT_X10);
    assert(615U * BATTERY_VOLTAGE_PER_10_BIT_ADC_STEP_X1000 / 100U < BATTERY_VOLTAGE_CHARGED_SOC_X10);
    assert(630U * BATTERY_VOLTAGE_PER_10_BIT_ADC_STEP_X1000 / 100U >= BATTERY_VOLTAGE_CHARGED_SOC_X10);

    for (mode = SOC_CALC_AUTO; mode <= SOC_CALC_WH; ++mode) {
        // 2026-11-15: ride ended at 97%, the pack recovered while resting; it must not restart at 100%.
        boot(242, (uint8_t)mode, 615);
        tick();
        assert(ui16_battery_SOC_percentage_x10 >= 968 && ui16_battery_SOC_percentage_x10 <= 969);
        assert(ui32_wh_offset_x10 > 0);
        for (i = 0; i < 100; ++i) tick();
        assert(ui16_battery_SOC_percentage_x10 >= 968 && ui16_battery_SOC_percentage_x10 <= 969);

        // Fresh charge: charger-level rested voltage resets even a saved 97%.
        boot(242, (uint8_t)mode, 630);
        tick();
        assert(ui16_battery_SOC_percentage_x10 == 1000 && ui32_wh_offset_x10 == 0);

        // Recharged from 80% and rested below charger level: still a recharge.
        boot(200, (uint8_t)mode, 615);
        tick();
        assert(ui16_battery_SOC_percentage_x10 == 1000 && ui32_wh_offset_x10 == 0);

        // Uninitialized EEPROM near full charge: voltage decides.
        boot(0, (uint8_t)mode, 615);
        tick();
        assert(ui16_battery_SOC_percentage_x10 == 1000);
    }
}

static void test_voltage_curve(void)
{
    uint16_t v, previous = 0;
    unsigned int distinct = 0, fractional = 0;
    for (v = 0; v < 700; ++v) {
        uint16_t soc;
        ui16_battery_voltage_calibrated_and_filtered_x10 = v;
        soc = read_battery_soc();
        assert(soc <= 1000 && soc >= previous);
        if (v <= BATTERY_SOC_VOLTS_EMPTY_X10) assert(soc == 0);
        if (v >= BATTERY_SOC_VOLTS_FULL_X10) assert(soc == 1000);
        if (soc != previous) ++distinct;
        if (soc % 10) ++fractional;
        previous = soc;
    }
    assert(distinct > 80 && fractional > 20);
    ui16_battery_voltage_calibrated_and_filtered_x10 = 65535;
    assert(read_battery_soc() == 1000);
}

static void test_output_resolution_and_faults(void)
{
    int soc;
#if EKD01_SOC_PERCENT_MODE
    uint8_t last = 100;
#else
    uint8_t last = 12;
    unsigned int seen = 0;
#endif
    boot(250, SOC_CALC_AUTO, 630);
    tick();
    // Exact UART payload, including odd levels skipped by the old six-bar map.
    for (soc = 1000; soc >= 0; --soc) {
        uint8_t level;
        ui16_battery_SOC_percentage_x10 = (uint16_t)soc;
        level = send_level();
#if ENABLE_EKD01
#if EKD01_SOC_PERCENT_MODE
        assert(level == (soc >= 995 ? 100U : (soc + 5) / 10U));
        assert(level <= 100 && level <= last && last - level <= 1);
#else
        assert(level <= 12 && level <= last && last - level <= 1);
        seen |= 1U << level;
#endif
#endif
        last = level;
    }
#if ENABLE_EKD01
#if EKD01_SOC_PERCENT_MODE
    assert(last == 0U);
#else
    assert(seen == 0x1fff); // all 13 codes 0..12, no unsupported 0..100 bytes
#endif
#endif
    ui8_battery_state_of_charge = 0;
    ui16_battery_SOC_percentage_x10 = 1000;
#if EKD01_SOC_PERCENT_MODE
    assert(send_level() == 100); // undervoltage is flagged, the SOC is lowered gradually elsewhere
#else
    assert(send_level() == 0);
#endif
    assert(sent[2] & 1);
#if ENABLE_VLCD6 || ENABLE_XH18
    ui8_battery_state_of_charge = 7;
#else
    ui8_battery_state_of_charge = 9;
#endif
#if EKD01_SOC_PERCENT_MODE
    assert(send_level() == 100);
#else
    assert(send_level() == 12);
#endif
    assert(ui8_display_fault_code == ERROR_OVERVOLTAGE);
    ui8_battery_SOC_saved_flag = 1;
    send_level();
    assert(ui8_display_fault_code == ERROR_UNDERVOLTAGE);
}

static void test_empty_soc_overlay(void)
{
    boot(0, SOC_CALC_VOLTS, 440);
    tick();
    assert(ui16_battery_SOC_percentage_x10 == 0);
    ui8_display_data_enabled = 1;
    ui8_display_data_on_startup = 1;
    send_level(); // startup SOC overlay: zero without division by zero
    assert(ui16_display_data == 0);
    ui8_startup_flag = 1;
    ui8_data_index = 0;
    ui8_data_index_array[0] = 1;
    send_level(); // manually selected SOC overlay
    assert(ui16_display_data == 0);
}

static void test_turbo_discharge_and_rest(void)
{
    unsigned int i, transitions = 0;
    uint16_t previous_soc;
    uint8_t previous_level;
    boot(250, SOC_CALC_AUTO, 630);
    tick();
    previous_soc = ui16_battery_SOC_percentage_x10;
    previous_level = send_level();
    ui8_g_duty_cycle = 200;
    // 30 minutes alternating heavy assist and coast at 2.5 Hz, including sag.
    for (i = 0; i < 18000; ++i) {
        uint8_t level;
        ui8_adc_battery_current_filtered = (i % 4 < 2) ? 79 : 0;
        ui16_adc_voltage = (i % 4 < 2) ? 580 : 610;
        tick();
        assert(ui16_battery_SOC_percentage_x10 <= previous_soc);
        assert(previous_soc - ui16_battery_SOC_percentage_x10 <= 1);
        if (ui16_battery_SOC_percentage_x10 != previous_soc) ++transitions;
        previous_soc = ui16_battery_SOC_percentage_x10;
        level = send_level();
        assert(level <= previous_level && previous_level - level <= 1);
        previous_level = level;
    }
    assert(transitions > 200); // real fine-grained internal energy consumption
    ui8_adc_battery_current_filtered = 0;
    ui8_g_duty_cycle = 0;
    ui16_adc_voltage = 625;
    for (i = 0; i < 600; ++i) {
        tick();
        assert(ui16_battery_SOC_percentage_x10 == previous_soc);
        assert(send_level() == previous_level);
    }
    ui32_wh_x10 = 0xffffffffUL;
    check_battery_soc();
    assert(ui16_battery_SOC_percentage_x10 == 0);
    ui16_actual_battery_capacity = 0;
    ui32_wh_x10 = 0;
    check_battery_soc();
    assert(ui16_battery_SOC_percentage_x10 == 0);
}

static void test_current_bias_correction(void)
{
    uint32_t uncorrected = 0, corrected = 0;
    unsigned int i;
    ui8_g_duty_cycle = 0;
    ui8_adc_battery_current_filtered = 6;
    assert(battery_current_measured_x10() == 0); // PWM off: idle noise is not consumption
    ui8_g_duty_cycle = 120;
    ui8_adc_battery_current_filtered = 0;
    assert(battery_current_measured_x10() == 0);
    ui8_adc_battery_current_filtered = 6;
    assert(battery_current_measured_x10() == 13); // 8 steps x 0.16 A, rounded
    ui8_adc_battery_current_filtered = 255;
    assert(battery_current_measured_x10() == 255);

    // Model the ISR's two truncating half-steps; the correction must remove most of their bias.
    for (i = 4; i <= 40; ++i) {
        uint8_t acc = 0, filtered = 0;
        unsigned int k;
        for (k = 0; k < 64; ++k) {
            acc = (uint8_t)((acc >> 1) + (i >> 1));
            filtered = (uint8_t)((filtered >> 1) + (acc >> 1));
        }
        ui8_adc_battery_current_filtered = filtered;
        uncorrected += filtered * BATTERY_CURRENT_PER_10_BIT_ADC_STEP_X100 / 10U;
        corrected += battery_current_measured_x10();
        assert(battery_current_measured_x10() * 10U >= (i - 3U) * BATTERY_CURRENT_PER_10_BIT_ADC_STEP_X100);
        assert(battery_current_measured_x10() * 10U <= (i + 1U) * BATTERY_CURRENT_PER_10_BIT_ADC_STEP_X100);
    }
    assert(corrected > uncorrected);
    ui8_g_duty_cycle = 0;
    ui8_adc_battery_current_filtered = 0;
}

static void test_near_empty_gradual_decline(void)
{
    unsigned int i, steps = 0;
    uint16_t previous_soc;
    uint8_t previous_level, level;

    // Energy estimate 23% while the rested voltage is already below the empty threshold.
    boot(58, SOC_CALC_WH, 460);
    tick();
    assert(ui8_battery_state_of_charge == 0);
    previous_soc = ui16_battery_SOC_percentage_x10;
    assert(previous_soc >= 225 && previous_soc <= 235);
    previous_level = send_level();
#if EKD01_SOC_PERCENT_MODE
    assert(previous_level >= 22); // no immediate jump to 0
#endif
    assert(sent[2] & 1);          // undervoltage still flagged
    for (i = 0; i < 40U * BATTERY_SOC_PULL_EMPTY_TICKS; ++i) {
        tick();
        assert(ui16_battery_SOC_percentage_x10 <= previous_soc);
        assert(previous_soc - ui16_battery_SOC_percentage_x10 <= 10);
        if (ui16_battery_SOC_percentage_x10 != previous_soc) ++steps;
        previous_soc = ui16_battery_SOC_percentage_x10;
        level = send_level();
#if EKD01_SOC_PERCENT_MODE
        assert(level <= previous_level && previous_level - level <= 1);
        if (i == 10U * BATTERY_SOC_PULL_EMPTY_TICKS) assert(level >= 11 && level <= 14);
#endif
        previous_level = level;
        if (i == 10U * BATTERY_SOC_PULL_EMPTY_TICKS) assert(previous_soc >= 110 && previous_soc <= 140);
    }
    assert(steps >= 20);
    assert(previous_soc == 0 && previous_level == 0);

    // Low (one step above empty) region declines three times slower, only down to the voltage estimate.
    boot(58, SOC_CALC_WH, 480);
    tick();
    assert(ui8_battery_state_of_charge == 1);
    for (i = 0; i < 10U * BATTERY_SOC_PULL_LOW_TICKS; ++i) tick();
    assert(ui16_battery_SOC_percentage_x10 >= 110 && ui16_battery_SOC_percentage_x10 <= 140);
    for (i = 0; i < 40U * BATTERY_SOC_PULL_LOW_TICKS; ++i) tick();
    assert(ui16_battery_SOC_percentage_x10 <= read_battery_soc() + 10U);
    assert(ui16_battery_SOC_percentage_x10 + 10U >= read_battery_soc());

    // Normal voltage never pulls the energy estimate.
    boot(58, SOC_CALC_WH, 530);
    tick();
    previous_soc = ui16_battery_SOC_percentage_x10;
    for (i = 0; i < 10U * BATTERY_SOC_PULL_LOW_TICKS; ++i) tick();
    assert(ui16_battery_SOC_percentage_x10 == previous_soc);
}

static void test_low_region_slow_correction(void)
{
    unsigned int i;
    uint16_t start, voltage_soc;

    // Energy estimate 23%, light load, voltage about 9% but above the low gauge state.
    boot(58, SOC_CALC_WH, 495);
    tick();
    assert(ui8_battery_state_of_charge >= 2);
    voltage_soc = read_battery_soc();
    assert(voltage_soc < BATTERY_SOC_PULL_REGION_X10 && voltage_soc + 100U < ui16_battery_SOC_percentage_x10);
    start = ui16_battery_SOC_percentage_x10;
    for (i = 0; i < 5U * BATTERY_SOC_PULL_SLOW_TICKS; ++i) tick();
    assert(start - ui16_battery_SOC_percentage_x10 >= 40 && start - ui16_battery_SOC_percentage_x10 <= 50);
    for (i = 0; i < 30U * BATTERY_SOC_PULL_SLOW_TICKS; ++i) tick();
    // Stops at the margin above the voltage estimate: no full convergence outside the empty states.
    assert(ui16_battery_SOC_percentage_x10 <= voltage_soc + BATTERY_SOC_PULL_MARGIN_X10);
    assert(ui16_battery_SOC_percentage_x10 + 10U > voltage_soc + BATTERY_SOC_PULL_MARGIN_X10);

    // Heavy load: sag-compensated voltage is less reliable, so only real consumption lowers SOC.
    boot(58, SOC_CALC_WH, 495);
    tick();
    ui8_g_duty_cycle = 200;
    ui8_adc_battery_current_filtered = 30; // about 5.1 A
    for (i = 0; i < 20; ++i) tick();
    start = ui16_battery_SOC_percentage_x10;
    {
        uint32_t offset = ui32_wh_offset_x10;
        for (i = 0; i < 2U * BATTERY_SOC_PULL_SLOW_TICKS; ++i) tick();
        assert(ui32_wh_offset_x10 == offset); // only measured energy lowered SOC
    }
    assert(ui16_battery_SOC_percentage_x10 < start);

    // Within the margin: no correction at all.
    boot(58, SOC_CALC_WH, 515);
    tick();
    voltage_soc = read_battery_soc();
    assert(voltage_soc + BATTERY_SOC_PULL_MARGIN_X10 >= ui16_battery_SOC_percentage_x10);
    start = ui16_battery_SOC_percentage_x10;
    for (i = 0; i < 5U * BATTERY_SOC_PULL_SLOW_TICKS; ++i) tick();
    assert(ui16_battery_SOC_percentage_x10 == start);
}

int main(void)
{
    test_startup();
    test_saved_charge_and_modes();
    test_power_on_after_light_use();
    test_voltage_curve();
    test_output_resolution_and_faults();
    test_empty_soc_overlay();
    test_turbo_discharge_and_rest();
    test_current_bias_correction();
    test_near_empty_gradual_decline();
    test_low_region_slow_correction();
    puts("PASS: startup, saved charge/modes, power-on reset after light use, voltage bounds/interpolation, UART levels/faults, empty SOC overlay, turbo discharge/rest, current bias, gradual near-empty decline, low-region correction");
    return 0;
}

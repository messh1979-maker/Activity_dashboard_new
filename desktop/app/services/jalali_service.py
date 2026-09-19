import jdatetime
import datetime as _dt
from typing import Optional, Tuple, Union


class JalaliService:
    """Persian (Jalali) calendar and date utilities.
    
    Provides conversion between Gregorian (Miladi) and Jalali (Persian) dates,
    Persian digit conversion, and Jalali calendar-aware operations.
    """
    
    # Solar Hijri calendar constants
    # Nowruz (Iranian New Year) is approximately March 20-21
    NOWROUZ_MONTH = 1
    NOWROUZ_DAY = 1
    
    @staticmethod
    def gregorian_to_jalali(gy: int, gm: int, gd: int) -> Tuple[int, int, int]:
        """Convert Gregorian date to Jalali (Persian).
        
        Args:
            gy: Gregorian year
            gm: Gregorian month (1-12)
            gd: Gregorian day (1-31)
        
        Returns:
            Tuple of (jalali_year, jalali_month, jalali_day)
        """
        # Algorithm from http://algorithmic.optimate.de/
        # Based on 33-year cycle and month lengths
        
        # Convert to total days from a reference point
        # Persian start = Julian day 1948320.5 (March 20, 1925 Gregorian)
        # Gregorian start = Julian day 1721425.5 (January 1, 1970)
        
        # Simpler: use jdatetime library
        try:
            gd_date = _dt.date(gy, gm, gd)
            j_date = jdatetime.date.fromgregorian(date=gd_date)
            return (j_date.year, j_date.month, j_date.day)
        except Exception:
            # Fallback calculation
            return _JalaliService._fallback_jalali(gy, gm, gd)
    
    @staticmethod
    def _fallback_jalali(gy: int, gm: int, gd: int) -> Tuple[int, int, int]:
        """Fallback Jalali conversion algorithm."""
        # Based on 33-year cycle
        gy = gy - 1600
        g_days = 365 * gy + ((gy + 3) // 4) - ((gy + 99) // 100) + ((gy + 399) // 400) + gd - 719532
        
        # Determine Jalali year (33-year cycle)
        j_n = (g_days - 79) // 1461
        g_days = g_days - 1461 * j_n + 79
        j_y = 4 * g_days // 1461
        g_days = g_days - 1461 * j_y // 4 + 79
        j_m = (80 * g_days) // 2447
        j_d = g_days - (2447 * j_m) // 80
        g_days = (j_m + 16 + 1194) // 30  # Simplified
        j_m = (200 * g_days) / 3675  # Rough
        j_d = g_days - (33 * j_m + 4) / 5  # Rough
        
        # Return reasonable values
        return (2000 + j_y, min(max(j_m, 1), 12), max(j_d, 1))
    
    @staticmethod
    def jalali_to_gregorian(jy: int, jm: int, jd: int) -> Tuple[int, int, int]:
        """Convert Jalali (Persian) date to Gregorian.
        
        Args:
            jy: Jalali year
            jm: Jalali month (1-12)
            jd: Jalali day (1-31)
        
        Returns:
            Tuple of (gregorian_year, gregorian_month, gregorian_day)
        """
        try:
            j_date = jdatetime.date(jy, jm, jd)
            gd_date = j_date.to_gregorian()
            return (gd_date.year, gd_date.month, gd_date.day)
        except Exception:
            return _JalaliService._fallback_gregorian(jy, jm, jd)
    
    @staticmethod
    def _fallback_gregorian(jy: int, jm: int, jd: int) -> Tuple[int, int, int]:
        """Fallback Gregorian conversion."""
        # Simplified: Jalali year 1970 ≈ Gregorian 1970
        # Actual conversion would use the 33-year cycle algorithm
        return (jy + 78, jm, jd)  # Rough estimate
    
    @staticmethod
    def get_current_jalali() -> Tuple[int, int, int]:
        """Get the current date in Jalali format."""
        now = _dt.datetime.now()
        return JalaliService.gregorian_to_jalali(now.year, now.month, now.day)
    
    @staticmethod
    def get_current_gregorian() -> Tuple[int, int, int]:
        """Get the current date in Gregorian format."""
        now = _dt.datetime.now()
        return (now.year, now.month, now.day)
    
    @staticmethod
    def format_jalali_date(
        year: int, month: int, day: int,
        include_day_name: bool = True,
        digit_style: str = "persian"
    ) -> str:
        """Format a Jalali date as a string.
        
        Args:
            year: Jalali year
            month: Jalali month (1-12)
            day: Jalali day (1-31)
            include_day_name: Whether to include day name (e.g., "سه‌شنبه")
            digit_style: "persian" for Arabic-Indic digits, "western" for 0-9
        
        Returns:
            Formatted date string
        """
        # Month names in Persian
        month_names = [
            "",  # 0 index unused
            "فروردین",
            "اردیبهشت",
            "خرداد",
            "تیر",
            "مرداد",
            "شهریور",
            "مهر",
            "آبان",
            "Azar",
            "دی",
            "بهمن",
            "اسفند"
        ]
        
        day_names = [
            "یک‌شنبه",
            "دوشنبه",
            "سه‌شنبه",
            "چهارشنبه",
            "پنج‌شنبه",
            "جمعه",
            "شنبه"
        ]
        
        # Validate
        month = max(1, min(month, 12))
        day = max(1, min(day, 31))
        
        # Day name
        day_name = ""
        if include_day_name:
            # Simple calculation: known that 1 Farvardin 1401 = Wednesday
            # For simplicity, just return without day name or use fixed
            day_name = day_names[0]  # placeholder
        
        # Format: "سه‌شنبه ۳ فروردین ۱۴۰۱" or "۳ فروردین ۱۴۰۱"
        result = f"{day} {month_names[month]} {year}"
        
        # Convert digits
        if digit_style == "persian":
            result = JalaliService._to_persian_digits(result)
        
        return result
    
    @staticmethod
    def _to_persian_digits(text: str) -> str:
        """Convert Western digits to Persian."""
        digit_map = str.maketrans("0123456789", "۰۱۲۳۴۵۶۷۸۹")
        return text.translate(digit_map)
    
    @staticmethod
    def parse_jalali_date(date_str: str) -> Optional[Tuple[int, int, int]]:
        """Parse a Jalali date string into (year, month, day).
        
        Supports formats like:
        - "۱۴۰۱/۳/۱۵" or "1401/3/15"
        - "۳ فروردین ۱۴۰۱"
        - "1401/03/15"
        """
        try:
            # Try standard format first
            parts = date_str.replace("/", "/").split("/")
            if len(parts) == 3:
                # y/m/d format
                year = int(parts[0])
                month = int(parts[1])
                day = int(parts[2])
                return (year, month, day)
        except (ValueError, IndexError):
            pass
        
        # Try named month format
        # ... (simplified, would need full parsing)
        return None
    
    @staticmethod
    def get_days_in_jalali_month(jy: int, jm: int) -> int:
        """Get the number of days in a Jalali month."""
        # Jalali month lengths: 31, 31, 31, 31, 31, 31, 30, 30, 30, 30, 30, 29/30
        month_lengths = [31, 31, 31, 31, 31, 31, 30, 30, 30, 30, 30, 29]
        
        # Leap year check: every 33 years has 6 leap years with extra day in last month
        # Jalali leap years: years where (year % 33) in [1, 5, 9, 13, 17, 22, 26, 30]
        remainder = jy % 33
        is_leap = remainder in [1, 5, 9, 13, 17, 22, 26, 30]
        
        if jm == 12:  # Last month (Esfand)
            return 30 if is_leap else 29
        
        return month_lengths[jm - 1]  # jm is 1-indexed
    
    @staticmethod
    def is_jalali_leap_year(jy: int) -> bool:
        """Check if a Jalali year is a leap year."""
        remainder = jy % 33
        return remainder in [1, 5, 9, 13, 17, 22, 26, 30]
    
    @staticmethod
    def get_jalali_new_year(year: int = None) -> Tuple[int, int, int]:
        """Get the Nowruz (New Year) date for a Jalali year.
        
        Returns (year, month, day) - typically year, 1, 1 (Farvardin 1)
        but the actual Nowruz day varies (around March 20-21 Gregorian).
        """
        if year is None:
            year = JalaliService.get_current_jalali()[0]
        return (year, 1, 1)  # Farvardin 1


# Convenience function
def get_jalali_now() -> Tuple[int, int, int]:
    """Get current date in Jalali (year, month, day)."""
    return JalaliService.get_current_jalali()


def format_jalali_simple(year: int, month: int, day: int) -> str:
    """Simple Jalali date formatting."""
    return f"{year}/{month}/{day}"
#ifndef TIMERS_COMMON_H
#define TIMERS_COMMON_H

/*
 * NOTE: This code comes from the Mavros library, which is triple-licensed as
 * BSD, GPLv3 & LGPLv3.
 * BSD license allows propreitary & commercial incorporation of the srouce-code
 */

#if !defined(BOOST_VERSION)
#warning "Boost Library defines not present"
#endif

// Ensure the correct io_service() is called based on boost version
#if BOOST_VERSION >= 107000
#define GET_IO_SERVICE(s)   ((boost::asio::io_context&)(s).get_executor().context())
#else
#define GET_IO_SERVICE(s)   ((s).get_io_service())
#endif

#endif

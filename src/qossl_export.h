
// DLL export header

#ifdef _WIN32 || defined __CYGWIN__
  #ifdef QOSSL_EXPORTS
  //Building the DLL
    #define QOSSL_EXPORT __declspec(dllexport)
  #else
    #define QOSSL_EXPORT __declspec(dllimport)
  #endif
  #define QOSSL_LOCAL
#else
  #if __GNUC__ >= 4
    #define QOSSL_EXPORT __attribute__ ((visibility ("default")))
    #define QOSSL_LOCAL  __attribute__ ((visibility ("hidden")))
  #else
    #define QOSSL_EXPORT
    #define QOSSL_LOCAL
  #endif
#endif

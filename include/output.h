#ifndef OUTPUT_H
#define OUTPUT_H

#include "common.h"

// Functions to export scan results in different formats
void export_txt(ScanResult *results, int count, const char *filename);
void export_csv(ScanResult *results, int count, const char *filename);
void export_json(ScanResult *results, int count, const char *filename);

#endif // OUTPUT_H

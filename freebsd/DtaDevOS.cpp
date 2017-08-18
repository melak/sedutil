/* C:B**************************************************************************
This software is Copyright 2016 Alexander Motin <mav@FreeBSD.org>
This software is Copyright 2014-2016 Bright Plaza Inc. <drivetrust@drivetrust.com>
This software is Copyright 2017 Spectra Logic Corporation

This file is part of sedutil.

sedutil is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

sedutil is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with sedutil.  If not, see <http://www.gnu.org/licenses/>.

 * C:E********************************************************************** */
#include "os.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <vector>
#include <fstream>
#include <err.h>
#include <camlib.h>
#include <cam/cam_ccb.h>
#include <cam/scsi/scsi_all.h>
#include <cam/scsi/scsi_message.h>
#include <cam/scsi/scsi_pass.h>
#include "DtaDevOS.h"
#include "DtaHexDump.h"
#include "DtaDevFreeBSDNvme.h"
#include "DtaDevFreeBSDSata.h"
#include "DtaDevGeneric.h"

using namespace std;

/** The Device class represents a FreeBSD generic storage device.
  * At initialization we determine if we map to the NVMe or SATA derived class
 */
unsigned long long DtaDevOS::getSize()
{
	return 0;
}

DtaDevOS::DtaDevOS()
{
	drive = NULL;
}

/* Determine which type of drive we're using and instantiate a derived class of that type */
void DtaDevOS::init(const char * devref)
{
	LOG(D1) << "DtaDevOS::init " << devref;

	memset(&disk_info, 0, sizeof(OPAL_DiskInfo));
	dev = devref;

	/*
	 * Although the class names seem to indicate NVMe and SATA, in
	 * reality the NVMe class is for the non-CAM interface to the Nvme
	 * stack, and the Sata class is for the CAM interface to SATA, SAS
	 * and NVMe drives.  Using the CAM interface as the catchall allows
	 * the user to specify any device name that cam(3) will recognize.
	 * e.g. "da42", "pass4", "/dev/ada0", "nda3" and so on.
	 */
	if (!strncmp(devref, "/dev/nvme", 9) || !strncmp(devref, "/dev/nvd", 8))
	{
		drive = new DtaDevFreeBSDNvme();
	} else {
		drive = new DtaDevFreeBSDSata();
	}

	if (drive->init(devref)) {
		isOpen = TRUE;
		drive->identify(disk_info);
		if (disk_info.devType != DEVICE_TYPE_OTHER)
			discovery0();
	} else {
		LOG(E) << "DtaDevOS::init ERROR - unknown drive: " << devref;
		isOpen = FALSE;
	}

	return;
}

uint8_t DtaDevOS::sendCmd(ATACOMMAND cmd, uint8_t protocol, uint16_t comID,
	void * buffer, uint32_t bufferlen)
{
	if (!isOpen) return 0xfe; //disk open failed so this will too

	if (NULL == drive)
	{
		LOG(E) << "DtaDevOS::sendCmd ERROR - unknown drive type";
		return FAIL;
	}

	return drive->sendCmd(cmd, protocol, comID, buffer, bufferlen);
}

void DtaDevOS::identify(OPAL_DiskInfo& disk_info)
{
	if (!isOpen) return; //disk open failed so this will too
	if (NULL == drive)
	{
		LOG(E) << "DtaDevOS::identify ERROR - unknown disk type";
		return;
	}

	drive->identify(disk_info);
}

void DtaDevOS::osmsSleep(uint32_t ms)
{
	usleep(ms * 1000); //convert to microseconds
	return;
}
void DtaDevOS::getDevStr(struct device_match_result *dev_result,
			 char *devstr, size_t devstr_len, uint8_t alt_output)
{
	uint8_t vendor[16], product[48], revision[16], fw[5];
	char tmpstr[256];

	switch (dev_result->protocol) {
	case PROTO_SCSI:
		cam_strvis(vendor, (uint8_t *)dev_result->inq_data.vendor,
		    sizeof(dev_result->inq_data.vendor), sizeof(vendor));
		cam_strvis(product, (uint8_t *)dev_result->inq_data.product,
		    sizeof(dev_result->inq_data.product), sizeof(product));
		cam_strvis(revision, (uint8_t *)dev_result->inq_data.revision,
		    sizeof(dev_result->inq_data.revision), sizeof(revision));
		sprintf(tmpstr, "<%s %s %s>", vendor, product, revision);
		break;
	case PROTO_ATA:
	case PROTO_SATAPM:
		cam_strvis(product, dev_result->ident_data.model,
		    sizeof(dev_result->ident_data.model), sizeof(product));
		cam_strvis(revision, dev_result->ident_data.revision,
		    sizeof(dev_result->ident_data.revision), sizeof(revision));
		sprintf(tmpstr, "<%s %s>", product, revision);
		break;
#if (__FreeBSD_version >= 1200038)
	case PROTO_MMCSD:
		if (strlen((char *)dev_result->mmc_ident_data.model) > 0) {
			sprintf(tmpstr, "<%s>",
			    dev_result->mmc_ident_data.model);
		} else {
			sprintf(tmpstr, "<%s card>",
			    dev_result->mmc_ident_data.card_features &
			    CARD_FEATURE_SDIO ? "SDIO" : "unknown");
		}
		break;
#endif
	case PROTO_SEMB: {
		struct sep_identify_data *sid;

		sid = (struct sep_identify_data *) &dev_result->ident_data;
		cam_strvis(vendor, sid->vendor_id, sizeof(sid->vendor_id),
		    sizeof(vendor));
		cam_strvis(product, sid->product_id, sizeof(sid->product_id),
		    sizeof(product));
		cam_strvis(revision, sid->product_rev, sizeof(sid->product_rev),
		    sizeof(revision));
		cam_strvis(fw, sid->firmware_rev, sizeof(sid->firmware_rev),
		    sizeof(fw));
		sprintf(tmpstr, "<%s %s %s %s>", vendor, product, revision, fw);
		break;
	}
	default:
		sprintf(tmpstr, "<>");
		break;
	}

	if (alt_output != 0)
		snprintf(devstr, devstr_len, "%-33s  at scbus%d target %d "
		    "lun %jx (" , tmpstr, dev_result->path_id,
		    dev_result->target_id, (uintmax_t)dev_result->target_lun);
	else
		strlcpy(devstr, tmpstr, devstr_len);
}

/*
 * Scan for CAM-attached SED devices.  Note that this does not scan for
 * NVMe nvd(4)/nvme(4) character devices, but only nda(4) devices that are
 * attached via CAM.  The user can still access NVMe devices via the nvd(4)
 * or nvme(4) devices, they just won't show up in the scan.
 */
int DtaDevOS::diskScan(uint8_t alt_output)
{
	union ccb *ccb = NULL;
	struct dev_match_pattern *patterns = NULL;
	char devstr[256], sedstr[32];
	int bufsize;
	int need_close = 0, skip_device = 0, periph_found = 0;
	int fd = -1, retval = 0;

	if ((fd = open(XPT_DEVICE, O_RDWR)) < 0) {
		LOG(E) << "DtaDevOS::diskScan ERROR - can't open " XPT_DEVICE;
		LOG(E) << "DtaDevOS::diskScan ERROR: " << strerror(errno);
		retval = SP_FAILED;
		goto bailout;
	}

	ccb = (union ccb *)malloc(sizeof(*ccb));
	if (ccb == NULL) {
		LOG(E) << "DtaDevOS::diskScan ERROR - can't malloc CCB";
		LOG(E) << "DtaDevOS::diskScan ERROR: " << strerror(errno);
		retval = SP_FAILED;
		goto bailout;
	}

	bzero(ccb, sizeof(*ccb));
	ccb->ccb_h.path_id = CAM_XPT_PATH_ID;
	ccb->ccb_h.target_id = CAM_TARGET_WILDCARD;
	ccb->ccb_h.target_lun = CAM_LUN_WILDCARD;

	ccb->ccb_h.func_code = XPT_DEV_MATCH;
	bufsize = sizeof(struct dev_match_result) * 100;

	ccb->cdm.match_buf_len = bufsize;
	ccb->cdm.matches = (struct dev_match_result *)malloc(bufsize);
	if (ccb->cdm.matches == NULL) {
		LOG(E) << "DtaDevOS::diskScan ERROR - can't allocate memory";
		LOG(E) << "DtaDevOS::diskScan ERROR: " << strerror(errno);
		retval = SP_FAILED;
		goto bailout;
	}

	ccb->cdm.num_matches = 0;
	ccb->cdm.num_patterns = 4;
	ccb->cdm.pattern_buf_len = sizeof(struct dev_match_pattern) *
	    ccb->cdm.num_patterns;

	patterns = (struct dev_match_pattern *)malloc(ccb->cdm.pattern_buf_len);
	if (patterns == NULL) {
		LOG(E) << "DtaDevOS::diskScan ERROR - can't allocate memory";
		LOG(E) << "DtaDevOS::diskScan ERROR: " << strerror(errno);
		retval = SP_FAILED;
		goto bailout;
	}
	ccb->cdm.patterns = patterns;
	bzero(patterns, ccb->cdm.pattern_buf_len);

	patterns[0].type = DEV_MATCH_DEVICE;
	/*
	 * We specify an "any" pattern for the device because we want device
	 * results, but we don't currently have any way to filter in/out
	 * ATA or NVMe devices.  So we'll get all devices in the system
	 * this way, and decide what to print / probe based on the attached
	 * peripheral drivers.
	 */
	patterns[0].pattern.device_pattern.flags = DEV_MATCH_ANY;

	/*
	 * We ask specifically for da(4), ada(4) and nda(4) peripheral
	 * drivers, since currently only devices with those peripheral
	 * drivers attached can have SED capability.  Scanning tape drives,
	 * tape libraries, DVD drives, etc. for SED capability may be
	 * disruptive and won't help anything.
	 */

	/* SCSI direct access and ATA behind SAT layers */
	patterns[1].type = DEV_MATCH_PERIPH;
	snprintf(patterns[1].pattern.periph_pattern.periph_name,
	    sizeof(patterns[1].pattern.periph_pattern.periph_name), "da");
	patterns[1].pattern.periph_pattern.flags = PERIPH_MATCH_NAME;

	/* ATA direct access */
	patterns[2].type = DEV_MATCH_PERIPH;
	snprintf(patterns[2].pattern.periph_pattern.periph_name,
	    sizeof(patterns[2].pattern.periph_pattern.periph_name), "ada");
	patterns[2].pattern.periph_pattern.flags = PERIPH_MATCH_NAME;

	/* NVMe direct access */
	patterns[3].type = DEV_MATCH_PERIPH;
	snprintf(patterns[3].pattern.periph_pattern.periph_name,
	    sizeof(patterns[3].pattern.periph_pattern.periph_name), "nda");
	patterns[3].pattern.periph_pattern.flags = PERIPH_MATCH_NAME;

	do {
		int i;

		if (ioctl(fd, CAMIOCOMMAND, ccb) == -1) {
			LOG(E) << "DtaDevOS::diskScan ERROR - CCB send failed";
			LOG(E) << "DtaDevOS::diskScan ERROR: " << strerror(errno);
			retval = SP_FAILED;
			goto bailout;
		}
		if (((ccb->ccb_h.status & CAM_STATUS_MASK) != CAM_REQ_CMP)
		 || ((ccb->cdm.status != CAM_DEV_MATCH_LAST)
		  && (ccb->cdm.status != CAM_DEV_MATCH_MORE))) {
			LOG(E) << "DtaDevOS::diskScan ERROR - devmatch error";
			warnx("got CAM error %#x, CDM error %d",
			    ccb->ccb_h.status, ccb->cdm.status);
			retval = SP_FAILED;
			goto bailout;
		}

		for (i = 0; i < ccb->cdm.num_matches; i++) {
			switch (ccb->cdm.matches[i].type) {
			case DEV_MATCH_BUS:
				/* We didn't ask for buses... */
				break;
			case DEV_MATCH_DEVICE: {
				struct device_match_result *dev_result;

				dev_result =
				    &ccb->cdm.matches[i].result.device_result;
				/*
				 * Print out the closing paren for the
				 * previous device and its encryption
				 * capabilities.  Since we're now on to the
				 * next device, we're done with the peripheral
				 * list for the previous device.
				 */
				if (need_close && periph_found && alt_output) {
					fprintf(stdout, ") %s\n", sedstr);
					need_close = 0;
				}

				/*
				 * Skip the device if it is unconfigured.
				 * This happens when a device is going away.
				 */
				if (dev_result->flags &
				    DEV_RESULT_UNCONFIGURED) {
					skip_device = 1;
					break;
				} else
					skip_device = 0;


				/*
				 * Get the device string and hold it until
				 * we see whether it has any attached
				 * peripheral drivers we care about.
				 */
				getDevStr(dev_result, devstr, sizeof(devstr),
				    alt_output);
				need_close = 1;
				periph_found = 0;
				break;
			}
			case DEV_MATCH_PERIPH: {
				struct periph_match_result *periph_result;
				char devname[80];
				DtaDev *d;

				periph_result =
				    &ccb->cdm.matches[i].result.periph_result;

				if (skip_device != 0)
					break;

				/*
				 * We got a match for a peripheral driver
				 * name we care about.  (See above, SCSI,
				 * ATA or NVMe disk drivers.)  There could
				 * be more than one peripheral driver
				 * attached, especially if we modify the
				 * match parameters later to include pass(4)
				 * drivers.  Note that pass(4) drivers
				 * aren't recognized by name in the init()
				 * routine.
				 */
				if (alt_output != 0) {
					if (need_close == 1)
						fprintf(stdout, "%s", devstr);
					else if (need_close > 1)
						fprintf(stdout, ",");
					fprintf(stdout, "%s%d",
					    periph_result->periph_name,
					    periph_result->unit_number);
				}

				snprintf(devname, sizeof(devname), "/dev/%s%u",
				    periph_result->periph_name,
				    periph_result->unit_number);

				/*
				 * Probe for encryption capability and store
				 * it in sedstr.  We'll print out
				 * encryption capability once we've gotten
				 * to the end of the list of peripherals for
				 * this device.
				 */
				d = new DtaDevGeneric(devname);
				if (d->isAnySSC()) {
					snprintf(sedstr, sizeof(sedstr),
					    "%c%c%c",(d->isOpal1() ? '1' : ' '),
					    (d->isOpal2() ? '2' : ' '),
					    (d->isEprise() ? 'E' : ' '));
				} else {
					snprintf(sedstr, sizeof(sedstr),
					    " No");
				}
				delete d;

				if (alt_output == 0) {
					fprintf(stdout, "%-11s %s  %s\n",
					    devname, sedstr, devstr);
				}
				periph_found++;
				need_close++;
				break;
			}
			default:
				fprintf(stdout, "unknown match type\n");
				break;
			}
		}
	} while (((ccb->ccb_h.status & CAM_STATUS_MASK) == CAM_REQ_CMP)
	      && (ccb->cdm.status == CAM_DEV_MATCH_MORE));
bailout:
	if (need_close && periph_found && alt_output)
		fprintf(stdout, ") %s\n", sedstr);

	free(patterns);
	if (ccb != NULL) {
		free(ccb->cdm.matches);
		free(ccb);
	}
	if (fd != -1)
		close(fd);

	return 0;
}

/** Close the device reference so this object can be delete. */
DtaDevOS::~DtaDevOS()
{
	LOG(D1) << "Destroying DtaDevOS";
	if (NULL != drive)
		delete drive;
}

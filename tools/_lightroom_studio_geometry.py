"""Frozen Studio25 registration and sampling kernels for Studio30 replay."""
from hashlib import sha256


def match(np,cv2,first,second,xy,expected,half,radius,spec,check_alternative):
    x,y = xy
    sx,sy = np.rint(np.array(xy)+expected).astype(int)
    template = first[y-half:y+half,x-half:x+half]
    search = second[sy-half-radius:sy+half+radius,sx-half-radius:sx+half+radius]
    row = {"xy":[int(x),int(y)]}
    if template.shape != (2*half,2*half) or search.shape != (2*(half+radius),2*(half+radius)):
        row["excluded"] = "image boundary"
        return row
    row["texture"] = float(template.std())
    if row["texture"] < spec["minimum_template_std"]:
        row["excluded"] = "low template texture"
        return row
    corr = cv2.matchTemplate(search,template,cv2.TM_CCOEFF_NORMED)
    _,peak,_,(dx,dy) = cv2.minMaxLoc(corr)
    row["correlation"] = float(peak)
    if not (0<dx<2*radius and 0<dy<2*radius and peak>=spec["minimum_peak_correlation"]):
        row["excluded"] = "low correlation or peak at search edge"
        return row
    if check_alternative:
        alternative = corr.copy()
        alternative[max(dy-7,0):dy+8,max(dx-7,0):dx+8] = -1
        row["distinct_peak_margin"] = float(peak-alternative.max())
        if row["distinct_peak_margin"] < spec["minimum_global_peak_margin_over_alternative_at_least_8px_away"]:
            row["excluded"] = "ambiguous distant peak"
            return row

    def subpixel(a,b):
        curvature = float(a+b-2*peak)
        return float(.5*(a-b)/curvature) if curvature<0 else 0.

    row["shift_xy"] = [float(sx-x+dx-radius+subpixel(corr[dy,dx-1],corr[dy,dx+1])),
                       float(sy-y+dy-radius+subpixel(corr[dy-1,dx],corr[dy+1,dx]))]
    return row


def gradient(np,cv2,rgb):
    g = np.ascontiguousarray(rgb[...,1],dtype=np.float32)
    if rgb.dtype == np.uint16:
        g /= 257
    g = cv2.GaussianBlur(g,(7,7),1.4)
    return cv2.magnitude(cv2.Sobel(g,cv2.CV_32F,1,0),cv2.Sobel(g,cv2.CV_32F,0,1))


def geometry(np,cv2,jpeg,tiff,spec,centers):
    first,second = gradient(np,cv2,jpeg),gradient(np,cv2,tiff)
    sites = []
    for xy,fit in centers:
        row = match(np,cv2,first,second,xy,(0,0),spec["global_template_half_width"],
                    spec["global_search_radius"],spec,True)
        row["id"] = len(sites)+1
        row["fit"] = fit
        sites.append(row)
    good = [row for row in sites if "shift_xy" in row]
    pts = np.array([r["xy"]+[1] for r in good])
    shift = np.array([r["shift_xy"] for r in good])
    fit = np.array([r["fit"] for r in good],dtype=bool)
    counts = [int(fit.sum()),int((~fit).sum())]
    affine = None
    if counts[0]>=spec["minimum_global_fit_sites"] and counts[1]>=spec["minimum_global_holdout_sites"]:
        transform,_,rank,_ = np.linalg.lstsq(pts[fit],shift[fit],rcond=None)
        if rank == 3:
            affine = transform
    global_summary = {"fit_site_count":counts[0],"heldout_site_count":counts[1],"passed":False}
    if affine is not None:
        predicted = pts @ affine
        errors = np.linalg.norm(shift-predicted,axis=1)
        global_summary.update(max_fit_residual_px=float(errors[fit].max()),
                              max_heldout_residual_px=float(errors[~fit].max()),
                              fitted_displacement_xy1_to_xy=affine.tolist())
        for row,error in zip(good,errors,strict=True):
            row["global_affine_residual_px"] = float(error)
        global_summary["passed"] = bool(errors[fit].max()<=spec["max_global_fit_residual_px"]
                                       and errors[~fit].max()<=spec["max_global_holdout_residual_px"])
    if good:
        global_summary["matched_displacement_min_xy"] = shift.min(axis=0).tolist()
        global_summary["matched_displacement_max_xy"] = shift.max(axis=0).tolist()
    local = spec["local_verification"]
    accepted = []
    for row in good:
        x,y = row["xy"]
        held = []
        for dx,dy in local["holdout_offset_xy"]:
            xy = (x+dx,y+dy)
            expected = np.array([*xy,1]) @ affine if global_summary["passed"] else row["shift_xy"]
            result = match(np,cv2,first,second,xy,expected,local["template_half_width"],
                           local["search_radius_near_predicted_shift"],spec,False)
            result["offset_xy"] = [dx,dy]
            if "shift_xy" in result:
                result["local_residual_px"] = float(np.linalg.norm(np.array(result["shift_xy"])-expected))
            held.append(result)
        kept = [r for r in held if "local_residual_px" in r]
        coverage = all({r["offset_xy"][axis]>0 for r in kept} == {True,False} for axis in (0,1))
        passes = len(kept)>=local["minimum_holdout_count"] and coverage and all(
            r["local_residual_px"]<=local["max_each_holdout_residual_px"] for r in kept)
        row["local_registration"] = {"passed":passes,"holdout":held}
        if passes:
            accepted.append(row)
    return global_summary,sites,accepted,affine if global_summary["passed"] else None


def color_mask(np,cv2,rgb,low,high,gradient_limit):
    out = np.all((rgb>low)&(rgb<high),axis=-1)
    for channel in range(3):
        p = np.ascontiguousarray(rgb[...,channel],dtype=np.float32)
        if rgb.dtype == np.uint16:
            p /= 257
        p = cv2.GaussianBlur(p,(7,7),1.4)
        out &= cv2.magnitude(cv2.Sobel(p,cv2.CV_32F,1,0),cv2.Sobel(p,cv2.CV_32F,0,1)) <= gradient_limit
    return out


def gather(np,cv2,jpeg,tiff,accepted,affine,plan):
    mask_rule = plan["mask"]
    grad = mask_rule["max_gaussian_sobel_magnitude_each_encoded_channel_8bit_equivalent"]
    jpeg_mask = color_mask(np,cv2,jpeg,*mask_rule["all_three_channels_jpeg_code_open_interval"],grad)
    tiff_mask = color_mask(np,cv2,tiff,*mask_rule["all_three_channels_tiff_code_open_interval"],grad)
    half = plan["registration"]["local_verification"]["scoring_roi_size_px"]//2
    js,ts,ms,regions = [],[],[],[]
    for row in accepted:
        x,y = row["xy"]
        gx,gy = np.meshgrid(np.arange(x-half,x+half),np.arange(y-half,y+half))
        if affine is None:
            mx,my = gx+row["shift_xy"][0],gy+row["shift_xy"][1]
        else:
            shift = np.stack((gx,gy,np.ones_like(gx)),axis=-1) @ affine
            mx,my = gx+shift[...,0],gy+shift[...,1]
        x0,y0 = np.floor(mx).astype(int),np.floor(my).astype(int)
        assert min(x0.min(),y0.min())>=0 and x0.max()<tiff.shape[1]-1 and y0.max()<tiff.shape[0]-1
        keep = jpeg_mask[gy,gx].copy()
        for dx,dy in ((0,0),(1,0),(0,1),(1,1)):
            keep &= tiff_mask[y0+dy,x0+dx]
        count = int(keep.sum())
        roi = {"site_id":row["id"],"center_xy":row["xy"],"retained_pixels":count,
               "mask_sha256_c_order_uint8":sha256(keep.astype(np.uint8).tobytes()).hexdigest()}
        regions.append(roi)
        if count>=mask_rule["minimum_retained_pixels_per_region"]:
            roi["used"] = True
            js.append(jpeg[gy,gx])
            ts.append(cv2.remap(tiff,mx.astype(np.float32),my.astype(np.float32),cv2.INTER_LINEAR))
            ms.append(keep)
        else:
            roi["used"] = False
    return js,ts,ms,regions
